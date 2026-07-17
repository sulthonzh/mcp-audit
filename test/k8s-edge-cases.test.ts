import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';
import { scanK8s } from '../src/scanners/k8s-scanner.ts';

async function makeTempDir(files: Record<string, string>): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'k8s-edge-'));
  for (const [name, content] of Object.entries(files)) {
    await fs.ensureDir(path.join(dir, path.dirname(name)));
    await fs.writeFile(path.join(dir, name), content);
  }
  return dir;
}

describe('k8s-scanner edge cases', () => {
  it('detects hostPath volume at pod spec level', async () => {
    const dir = await makeTempDir({
      'pod.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-hostpath
spec:
  containers:
    - name: app
      image: app:1.0
  volumes:
    - name: host
      hostPath:
        path: /var/lib/elastic
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'hostPath volume mounted'));
      assert.ok(result.issues.some(i => i.category === 'filesystem'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects hostNetwork enabled', async () => {
    const dir = await makeTempDir({
      'deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hostnet-deploy
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
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'hostNetwork enabled'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects hostPID enabled', async () => {
    const dir = await makeTempDir({
      'pod.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: hostpid-pod
spec:
  hostPID: true
  containers:
    - name: app
      image: app:1.0
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'hostPID enabled'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects hostIPC enabled', async () => {
    const dir = await makeTempDir({
      'pod.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: hostipc-pod
spec:
  hostIPC: true
  containers:
    - name: app
      image: app:1.0
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'hostIPC enabled'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles services with empty spec', async () => {
    const dir = await makeTempDir({
      'svc.yaml': `
apiVersion: v1
kind: Service
metadata:
  name: empty-svc
spec: {}
`,
    });

    try {
      const result = await scanK8s(dir);
      // Should not crash, just skip
      assert.ok(Array.isArray(result.issues));
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles deployment with no template spec', async () => {
    const dir = await makeTempDir({
      'deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: no-template
spec:
`,
    });

    try {
      const result = await scanK8s(dir);
      // Should not crash, should return empty issues
      assert.ok(Array.isArray(result.issues));
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles malformed YAML (invalid kind)', async () => {
    const dir = await makeTempDir({
      'bad.yaml': `
apiVersion: v1
kind: InvalidKind
metadata:
  name: bad-kind
spec:
  containers:
    - name: app
      image: app:1.0
`,
    });

    try {
      const result = await scanK8s(dir);
      // Should handle gracefully
      assert.ok(Array.isArray(result.issues));
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles empty docs in multi-doc YAML', async () => {
    const dir = await makeTempDir({
      'multi.yaml': `
---
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
---
apiVersion: v1
kind: Service
metadata:
  name: svc-a
spec:
  type: NodePort
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

  it('scans pod kind correctly', async () => {
    const dir = await makeTempDir({
      'pod.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: direct-pod
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
    - name: app
      image: app:1.0
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'hostNetwork enabled'));
      assert.ok(result.issues.some(i => i.title === 'hostPID enabled'));
      assert.ok(result.issues.some(i => i.title === 'hostIPC enabled'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('scans statefulset correctly', async () => {
    const dir = await makeTempDir({
      'sts.yaml': `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: sts-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
          securityContext:
            privileged: true
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'Privileged container'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('scans daemonset correctly', async () => {
    const dir = await makeTempDir({
      'ds.yaml': `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ds-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
          securityContext:
            runAsNonRoot: false
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'Container may run as root'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('scans replicaset correctly', async () => {
    const dir = await makeTempDir({
      'rs.yaml': `
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: rs-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
          securityContext:
            privileged: true
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'Privileged container'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('scans job correctly', async () => {
    const dir = await makeTempDir({
      'job.yaml': `
apiVersion: batch/v1
kind: Job
metadata:
  name: job-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
          securityContext:
            privileged: true
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'Privileged container'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles error during file reading', async () => {
    const dir = await makeTempDir({
      'deploy.yaml': `
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
      // Modify file to be unreadable
      await fs.chmod(path.join(dir, 'deploy.yaml'), 0o000);
      const result = await scanK8s(dir);
      // Should handle error gracefully
      assert.ok(Array.isArray(result.issues));
    } finally {
      await fs.remove(dir);
    }
  });

  it('scans deployment with nested init containers', async () => {
    const dir = await makeTempDir({
      'deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: init-deploy
spec:
  template:
    spec:
      initContainers:
        - name: init
          image: init:1.0
          securityContext:
            privileged: true
      containers:
        - name: app
          image: app:1.0
          securityContext:
            runAsNonRoot: false
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'Privileged container'));
      assert.ok(result.issues.some(i => i.title === 'Container may run as root'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('scans deployment with init containers + containers', async () => {
    const dir = await makeTempDir({
      'deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mixed-containers
spec:
  template:
    spec:
      initContainers:
        - name: init
          image: init:1.0
          securityContext:
            privileged: true
      containers:
        - name: app
          image: app:1.0
          securityContext:
            runAsNonRoot: true
`,
    });

    try {
      const result = await scanK8s(dir);
      // Should only flag privileged init container, not app
      const privilegedIssues = result.issues.filter(i => i.title === 'Privileged container');
      assert.ok(privilegedIssues.length > 0);
      assert.ok(privilegedIssues[0].description.includes('init'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects multiple issues in single manifest', async () => {
    const dir = await makeTempDir({
      'multi-issue.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: multi-issue
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      containers:
        - name: app
          image: app:1.0
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
          env:
            - name: PASSWORD
              value: supersecret
`,
    });

    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'hostNetwork enabled'));
      assert.ok(result.issues.some(i => i.title === 'hostPID enabled'));
      assert.ok(result.issues.some(i => i.title === 'hostIPC enabled'));
      assert.ok(result.issues.some(i => i.title === 'Container may run as root'));
      assert.ok(result.issues.some(i => i.title === 'Hardcoded secret in env var'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('scans directory with no K8s manifests', async () => {
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
});
