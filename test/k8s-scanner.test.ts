import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';
import { scanK8s } from '../src/scanners/k8s-scanner';

async function makeTempDir(files: Record<string, string>): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'k8s-test-'));
  for (const [name, content] of Object.entries(files)) {
    await fs.ensureDir(path.join(dir, path.dirname(name)));
    await fs.writeFile(path.join(dir, name), content);
  }
  return dir;
}

describe('k8s-scanner', () => {
  it('finds privileged container', async () => {
    const dir = await makeTempDir({
      'deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
          securityContext:
            privileged: true
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'Privileged container'));
      assert.ok(result.issues.some(i => i.type === 'high'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('finds hardcoded secrets in env vars', async () => {
    const dir = await makeTempDir({
      'pod.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: leaky-pod
spec:
  containers:
    - name: app
      image: myapp:1.0
      env:
        - name: DB_PASSWORD
          value: "supersecret123"
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'Hardcoded secret in env var'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('finds no resource limits', async () => {
    const dir = await makeTempDir({
      'deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nolimits
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'No resource limits set'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('finds LoadBalancer service', async () => {
    const dir = await makeTempDir({
      'svc.yaml': `
apiVersion: v1
kind: Service
metadata:
  name: my-svc
spec:
  type: LoadBalancer
  ports:
    - port: 80
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'Service exposed via LoadBalancer'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('finds latest tag', async () => {
    const dir = await makeTempDir({
      'deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: latest-tag
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:latest
          resources:
            limits:
              cpu: "100m"
              memory: "128Mi"
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'Using latest or untagged image'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('ignores non-K8s YAML files', async () => {
    const dir = await makeTempDir({
      'docker-compose.yaml': `
version: "3"
services:
  web:
    image: nginx
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.equal(result.summary.configFilesFound, 0);
      assert.equal(result.issues.length, 0);
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles multi-doc YAML', async () => {
    const dir = await makeTempDir({
      'multi.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: pod-a
spec:
  hostNetwork: true
  containers:
    - name: app
      image: app:1.0
---
apiVersion: v1
kind: Service
metadata:
  name: svc-a
spec:
  type: NodePort
  ports:
    - port: 80
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'hostNetwork enabled'));
      assert.ok(result.issues.some(i => i.title === 'Service uses NodePort'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('scans a clean manifest with minimal issues', async () => {
    const dir = await makeTempDir({
      'clean.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: clean-app
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: myapp:1.2.3
          resources:
            requests:
              cpu: "50m"
              memory: "64Mi"
            limits:
              cpu: "200m"
              memory: "256Mi"
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
`,
    });

    try {
      const result = await scanK8s(dir);
      // Pod-level runAsNonRoot won't satisfy container-level check — that's fine
      // Just verify score is reasonable
      assert.ok(result.score >= 70, "Score was " + result.score);
      assert.ok(result.issues.length <= 2, "Too many issues for a clean manifest");
    } finally {
      await fs.remove(dir);
    }
  });
});
