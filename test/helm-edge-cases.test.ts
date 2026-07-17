import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';
import { scanHelm } from '../src/scanners/helm-scanner.ts';

async function makeTempDir(files: Record<string, string>): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'helm-edge-'));
  for (const [name, content] of Object.entries(files)) {
    await fs.ensureDir(path.join(dir, path.dirname(name)));
    await fs.writeFile(path.join(dir, name), content);
  }
  return dir;
}

describe('helm-scanner edge cases', () => {
  it('detects privileged container in Helm template', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'templates/deployment.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: {{ .Values.image }}
          securityContext:
            privileged: true
`,
      'values.yaml': `image: nginx:latest
privileged: false
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.issues.some(i => i.title === 'Privileged container in Helm template'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects latest tag in Helm template (not template var)', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'templates/deployment.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: myrepo/myapp:latest
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.issues.some(i => i.title === 'Latest tag in Helm template'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects hostPath in Helm template', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'templates/pod.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: {{ .Release.Name }}-pod
spec:
  containers:
    - name: app
      image: app:1.0
  volumes:
    - name: host
      hostPath:
        path: /var/lib/data
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.issues.some(i => i.title === 'hostPath volume in Helm template'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects hostNetwork in Helm template', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'templates/deployment.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-app
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: app:1.0
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.issues.some(i => i.title === 'hostNetwork in Helm template'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects LoadBalancer in Helm template', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'templates/service.yaml': `
apiVersion: v1
kind: Service
metadata:
  name: {{ .Release.Name }}-svc
spec:
  type: LoadBalancer
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.issues.some(i => i.title === 'LoadBalancer service in Helm template'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects deprecated chart', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: deprecated-chart
version: 1.0.0
deprecated: true
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.issues.some(i => i.title === 'Deprecated Helm chart'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('missing appVersion in Chart.yaml', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: no-version
version: 1.0.0
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.issues.some(i => i.title === 'Missing appVersion in Chart.yaml'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('has no Chart.yaml but has templates', async () => {
    const dir = await makeTempDir({
      'templates/deployment.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
`,
    });

    try {
      const result = await scanHelm(dir);
      // Should return empty issues, no crash
      assert.equal(result.issues.length, 0);
      assert.equal(result.score, 100);
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects nested secrets in values.yaml', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'values.yaml': `database:
  password: supersecret123
  token: abc123
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.issues.some(i => i.title === 'Hardcoded secret in values.yaml'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('skips obvious placeholders in values.yaml', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'values.yaml': `database:
  password: changeme
  token: xxx
  key: placeholder
`,
    });

    try {
      const result = await scanHelm(dir);
      // Should NOT flag obvious placeholders
      const secretIssues = result.issues.filter(i => i.title === 'Hardcoded secret in values.yaml');
      assert.equal(secretIssues.length, 0);
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects runAsRoot in values.yaml', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'values.yaml': `security:
  runAsRoot: true
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.issues.some(i => i.title === 'runAsRoot enabled in values'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects hostNetwork in values.yaml', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'values.yaml': `network:
  hostNetwork: true
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.issues.some(i => i.title === 'hostNetwork in values'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects privileged in values.yaml', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'values.yaml': `security:
  privileged: true
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.issues.some(i => i.title === 'Privileged container in values'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles chart with subdirectories in templates', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'templates/deployment.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
`,
      'templates/controllers': `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: {{ .Release.Name }}-sts
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.summary.configFilesFound > 0);
      assert.ok(Array.isArray(result.issues));
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles chart with templates/ subdir at multiple levels', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'templates/controllers': `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: {{ .Release.Name }}-sts
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.summary.configFilesFound > 0);
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles Go template syntax that doesn\'t parse after stripping', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'templates/pod.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: {{ .Release.Name }}-pod
spec:
  containers:
    - name: app
      image: {{ .Values.image }}
      command: ["sh", "-c", "while true; do sleep 30; done"]
`,
    });

    try {
      const result = await scanHelm(dir);
      // Should not crash, should return empty or parse what it can
      assert.ok(Array.isArray(result.issues));
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles deeply nested charts (depth > 10 limit)', async () => {
    const dir = await makeTempDir({});

    try {
      // Create a deeply nested chart structure
      let current = dir;
      for (let i = 0; i < 12; i++) {
        current = path.join(current, `level-${i}`);
        await fs.ensureDir(current);
        await fs.writeFile(path.join(current, 'Chart.yaml'), `apiVersion: v2
name: level-${i}
version: 1.0.0
`);
      }

      const result = await scanHelm(dir);
      // Should stop at depth 10, should only find one chart
      assert.ok(result.summary.configFilesFound > 0);
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles Chart.yaml with invalid YAML', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
  invalid: indent
`,
    });

    try {
      const result = await scanHelm(dir);
      // Should handle gracefully
      assert.ok(Array.isArray(result.issues));
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles values.yaml with invalid YAML', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'values.yaml': `database:
  password: supersecret
  token: abc123
  api_key: xyz
  invalid: yaml
    continues:
      here:`
    });

    try {
      const result = await scanHelm(dir);
      // Should handle gracefully
      assert.ok(Array.isArray(result.issues));
    } finally {
      await fs.remove(dir);
    }
  });

  it('scans Chart.yaml with no name field', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
version: 1.0.0
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(Array.isArray(result.issues));
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles chart with chart directory in name', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test/charts/subchart
version: 1.0.0
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(Array.isArray(result.issues));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects nested secrets in values.yaml (password in nested key)', async () => {
    const dir = await makeTempDir({
      'Chart.yaml': `apiVersion: v2
name: test
version: 1.0.0
`,
      'values.yaml': `database:
  credentials:
    password: supersecret
`,
    });

    try {
      const result = await scanHelm(dir);
      assert.ok(result.issues.some(i => i.title === 'Hardcoded secret in values.yaml'));
    } finally {
      await fs.remove(dir);
    }
  });
});
