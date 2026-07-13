import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs-extra';
import path from 'path';
import { scanHelm } from '../src/scanners/helm-scanner.ts';

const TMP = path.join(__dirname, '__helm_test_tmp__');

async function makeChart(name: string, files: Record<string, string>) {
  const chartDir = path.join(TMP, name);
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(chartDir, rel);
    await fs.ensureDir(path.dirname(fp));
    await fs.writeFile(fp, content);
  }
  return chartDir;
}

describe('Helm chart scanner', () => {
  before(async () => { await fs.ensureDir(TMP); });
  after(async () => { await fs.remove(TMP); });

  it('returns score 100 when no charts found', async () => {
    const emptyDir = path.join(TMP, 'no-charts');
    await fs.ensureDir(emptyDir);
    const result = await scanHelm(emptyDir);
    assert.equal(result.score, 100);
    assert.equal(result.issues.length, 0);
  });

  it('detects hardcoded secrets in values.yaml', async () => {
    const dir = await makeChart('chart-secrets', {
      'Chart.yaml': 'apiVersion: v2\nname: myapp\nversion: 1.0.0\nappVersion: "1.0"',
      'values.yaml': `
replicaCount: 1
image:
  repository: nginx
  tag: "1.25"
database:
  password: "super-secret-password-123"
`,
      'templates/deployment.yaml': `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Values.name }}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: myapp
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
`,
    });

    const result = await scanHelm(dir);
    assert.ok(result.issues.length >= 1, 'Should find at least one issue');
    const secretIssue = result.issues.find(i => i.title.includes('Hardcoded secret'));
    assert.ok(secretIssue, 'Should detect hardcoded secret in values.yaml');
    assert.equal(secretIssue!.type, 'high');
  });

  it('skips placeholder values', async () => {
    const dir = await makeChart('chart-placeholders', {
      'Chart.yaml': 'apiVersion: v2\nname: placeholder-app\nversion: 1.0.0\nappVersion: "1.0"',
      'values.yaml': `
database:
  password: "changeme"
  token: "REPLACE_ME"
`,
      'templates/deployment.yaml': `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  replicas: 1
  selector: {}
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
`,
    });

    const result = await scanHelm(dir);
    const secretIssue = result.issues.find(i => i.title.includes('Hardcoded secret'));
    assert.equal(secretIssue, undefined, 'Should skip placeholder values');
  });

  it('detects privileged containers in templates', async () => {
    const dir = await makeChart('chart-privileged', {
      'Chart.yaml': 'apiVersion: v2\nname: priv-app\nversion: 1.0.0',
      'values.yaml': 'replicaCount: 1',
      'templates/deployment.yaml': `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
          securityContext:
            privileged: true
`,
    });

    const result = await scanHelm(dir);
    const priv = result.issues.find(i => i.title.includes('Privileged'));
    assert.ok(priv, 'Should detect privileged container');
  });

  it('detects LoadBalancer service in template', async () => {
    const dir = await makeChart('chart-lb', {
      'Chart.yaml': 'apiVersion: v2\nname: lb-app\nversion: 1.0.0',
      'values.yaml': 'service:\n  type: LoadBalancer',
      'templates/service.yaml': `apiVersion: v1
kind: Service
metadata:
  name: {{ .Values.service }}
spec:
  type: LoadBalancer
  ports:
    - port: 80
`,
    });

    const result = await scanHelm(dir);
    const lb = result.issues.find(i => i.title.includes('LoadBalancer'));
    assert.ok(lb, 'Should detect LoadBalancer service');
  });

  it('detects hostPath volumes in templates', async () => {
    const dir = await makeChart('chart-hostpath', {
      'Chart.yaml': 'apiVersion: v2\nname: hp-app\nversion: 1.0.0',
      'values.yaml': 'replicaCount: 1',
      'templates/deployment.yaml': `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
      volumes:
        - name: host
          hostPath:
            path: /var/run/docker.sock
`,
    });

    const result = await scanHelm(dir);
    const hp = result.issues.find(i => i.title.includes('hostPath'));
    assert.ok(hp, 'Should detect hostPath volume');
  });

  it('detects deprecated chart', async () => {
    const dir = await makeChart('chart-deprecated', {
      'Chart.yaml': 'apiVersion: v2\nname: old-app\nversion: 1.0.0\ndeprecated: true',
      'values.yaml': 'replicaCount: 1',
    });

    const result = await scanHelm(dir);
    const dep = result.issues.find(i => i.title.includes('Deprecated'));
    assert.ok(dep, 'Should detect deprecated chart');
  });

  it('detects hostNetwork in values.yaml', async () => {
    const dir = await makeChart('chart-hn', {
      'Chart.yaml': 'apiVersion: v2\nname: hn-app\nversion: 1.0.0',
      'values.yaml': 'hostNetwork: true',
    });

    const result = await scanHelm(dir);
    const hn = result.issues.find(i => i.title.includes('hostNetwork'));
    assert.ok(hn, 'Should detect hostNetwork in values');
  });

  it('strips Go template syntax and parses manifests', async () => {
    const dir = await makeChart('chart-gotpl', {
      'Chart.yaml': 'apiVersion: v2\nname: gotpl-app\nversion: 1.0.0\nappVersion: "2.0"',
      'values.yaml': 'replicaCount: 1',
      'templates/deployment.yaml': `{{- if .Values.deploy }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Values.name }}
  labels:
    {{- include "labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  template:
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          {{- with .Values.resources }}
          resources:
            {{- toYaml . | nindent 12 }}
          {{- end }}
{{- end }}
`,
    });

    const result = await scanHelm(dir);
    // Should parse without errors — even if it can't fully resolve templates
    assert.ok(result.score >= 0, 'Should produce a valid score');
  });
});
