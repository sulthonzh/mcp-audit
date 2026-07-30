import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';
import { scanK8s } from '../src/scanners/k8s-scanner.ts';

// ─── k8s-scanner coverage gaps round 4 ───
// Targeting uncovered branches at lines 88, 99, 101, 106, 173, 210-211,
// 283-285, 317-319, 325, 350-351, 396

async function makeTmp(files: Record<string, string>): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'k8s-cov4-'));
  for (const [name, content] of Object.entries(files)) {
    await fs.ensureDir(path.join(dir, path.dirname(name)));
    await fs.writeFile(path.join(dir, name), content);
  }
  return dir;
}

describe('k8s-scanner coverage gaps round 4', () => {

  // ─── Line 88: Pod with null/missing spec → `manifest.spec as K8sPodSpec ?? null` ───
  it('handles Pod with no spec (nullish coalescing to null)', async () => {
    const dir = await makeTmp({
      'pod-no-spec.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: no-spec
`,
    });
    try {
      const result = await scanK8s(dir);
      // Pod has no spec → extractPodSpec returns null → no container issues
      assert.ok(Array.isArray(result.issues));
      assert.equal(result.summary.configFilesFound, 1);
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Line 99: !podSpec (extractPodSpec returns null for deployment with no template spec) ───
  it('handles Deployment with null podSpec from missing template.spec', async () => {
    const dir = await makeTmp({
      'deploy-no-template.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: no-template-spec
spec:
  replicas: 3
`,
    });
    try {
      const result = await scanK8s(dir);
      // extractPodSpec returns null for deployment without template.spec
      assert.ok(Array.isArray(result.issues));
      // No container checks run since podSpec is null
      assert.ok(!result.issues.some(i => i.title === 'Container may run as root'));
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Line 101: containers ?? [] and initContainers ?? [] ───
  it('handles pod spec with no containers key (nullish coalescing to [])', async () => {
    const dir = await makeTmp({
      'pod-no-containers.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: no-containers
spec:
  hostNetwork: true
`,
    });
    try {
      const result = await scanK8s(dir);
      // No containers → no container issues, but hostNetwork still detected
      assert.ok(result.issues.some(i => i.title === 'hostNetwork enabled'));
      assert.ok(!result.issues.some(i => i.title === 'Container may run as root'));
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Line 106: ctr.name ?? 'unnamed-container' ───
  it('uses unnamed-container fallback when container has no name', async () => {
    const dir = await makeTmp({
      'pod-no-name.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
    - image: nginx:1.25
      securityContext:
        privileged: true
`,
    });
    try {
      const result = await scanK8s(dir);
      const privileged = result.issues.find(i => i.title === 'Privileged container');
      assert.ok(privileged);
      assert.ok(privileged!.description.includes('unnamed-container'));
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Line 173: untagged image with '/' but no ':' (e.g., "myregistry/app") ───
  it('detects untagged image with slash but no tag colon', async () => {
    const dir = await makeTmp({
      'deploy-untagged.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: untagged
spec:
  template:
    spec:
      containers:
        - name: app
          image: myregistry/app
          securityContext:
            runAsNonRoot: true
          resources:
            limits:
              cpu: "100m"
            requests:
              cpu: "50m"
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
      // Image "myregistry/app" has '/' but no ':' → should trigger untagged warning
      assert.ok(
        result.issues.some(i => i.title === 'Using latest or untagged image'),
        'Should detect untagged image with slash'
      );
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Lines 210-211: container WITH liveness and readiness probes (false branch) ───
  it('does not report missing probes when both are present', async () => {
    const dir = await makeTmp({
      'deploy-with-probes.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: with-probes
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
          securityContext:
            runAsNonRoot: true
          resources:
            limits:
              cpu: "100m"
            requests:
              cpu: "50m"
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
      assert.ok(!result.issues.some(i => i.title === 'No liveness probe'));
      assert.ok(!result.issues.some(i => i.title === 'No readiness probe'));
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Lines 283-285: Service with spec but type is ClusterIP (neither LoadBalancer nor NodePort) ───
  it('does not flag ClusterIP service', async () => {
    const dir = await makeTmp({
      'svc-clusterip.yaml': `
apiVersion: v1
kind: Service
metadata:
  name: internal-svc
spec:
  type: ClusterIP
  ports:
    - port: 80
`,
    });
    try {
      const result = await scanK8s(dir);
      assert.ok(!result.issues.some(i => i.title === 'Service exposed via LoadBalancer'));
      assert.ok(!result.issues.some(i => i.title === 'Service uses NodePort'));
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Line 325: checkManifest guard (!doc) — null doc from YAML ───
  it('handles null doc in multi-doc YAML gracefully', async () => {
    const dir = await makeTmp({
      'null-doc.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: real-pod
spec:
  containers:
    - name: app
      image: app:1.0
---
null
`,
    });
    try {
      const result = await scanK8s(dir);
      // Should not crash on null doc
      assert.ok(Array.isArray(result.issues));
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Lines 350-351: findYamlFiles walk — non-yaml file skipped in directory mode ───
  it('skips non-yaml files when walking directory', async () => {
    const dir = await makeTmp({
      'deploy.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
    - name: app
      image: app:1.0
`,
      'readme.md': '# Project\n\nSome docs',
      'config.json': '{"key": "value"}',
      'script.sh': '#!/bin/bash\necho hello',
    });
    try {
      const result = await scanK8s(dir);
      // Only deploy.yaml should be scanned
      assert.equal(result.summary.configFilesFound, 1);
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Line 396: catch block — broken symlink causes error ───
  it('handles broken symlink during scan', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'k8s-err-'));
    const symlinkPath = path.join(dir, 'broken-link.yaml');
    try {
      await fs.symlink('/nonexistent/target/file.yaml', symlinkPath);
      const result = await scanK8s(dir);
      // Should handle error gracefully
      assert.ok(Array.isArray(result.issues));
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Volume mount at /host path (suspicious mount) ───
  it('detects suspicious host mount path starting with /host', async () => {
    const dir = await makeTmp({
      'deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: host-mount
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
          securityContext:
            runAsNonRoot: true
          resources:
            limits:
              cpu: "100m"
            requests:
              cpu: "50m"
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
          volumeMounts:
            - name: host
              mountPath: /host/etc
`,
    });
    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'Suspicious host mount path'));
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Service with no metadata.name → uses 'unnamed-service' fallback ───
  it('uses unnamed-service fallback for service without name', async () => {
    const dir = await makeTmp({
      'svc-no-name.yaml': `
apiVersion: v1
kind: Service
spec:
  type: LoadBalancer
  ports:
    - port: 443
`,
    });
    try {
      const result = await scanK8s(dir);
      const lb = result.issues.find(i => i.title === 'Service exposed via LoadBalancer');
      assert.ok(lb);
      assert.ok(lb!.description.includes('unnamed-service'));
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Pod with no resource requests ───
  it('detects missing resource requests separately from limits', async () => {
    const dir = await makeTmp({
      'deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: no-requests
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
          securityContext:
            runAsNonRoot: true
          resources:
            limits:
              cpu: "100m"
`,
    });
    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'No resource requests set'));
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Init container resource requests check ───
  it('checks init containers for resource issues', async () => {
    const dir = await makeTmp({
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
            runAsNonRoot: true
          resources:
            limits:
              memory: "128Mi"
      containers:
        - name: app
          image: app:1.0
          securityContext:
            runAsNonRoot: true
          resources:
            limits:
              cpu: "100m"
            requests:
              cpu: "50m"
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
      assert.ok(result.issues.some(i => i.title === 'No resource requests set'));
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Walk skips hidden dirs and node_modules ───
  it('skips hidden directories and node_modules during walk', async () => {
    const dir = await makeTmp({
      'deploy.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: visible
spec:
  containers:
    - name: app
      image: app:1.0
`,
      '.hidden/secret.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: hidden
spec:
  hostNetwork: true
  containers:
    - name: app
      image: app:1.0
`,
      'node_modules/pkg/deploy.yaml': `
apiVersion: v1
kind: Pod
metadata:
  name: nodemod
spec:
  hostPID: true
  containers:
    - name: app
      image: app:1.0
`,
    });
    try {
      const result = await scanK8s(dir);
      // Only deploy.yaml should be scanned, hidden/node_modules skipped
      assert.ok(!result.issues.some(i => i.title === 'hostNetwork enabled'));
      assert.ok(!result.issues.some(i => i.title === 'hostPID enabled'));
    } finally {
      await fs.remove(dir);
    }
  });

  // ─── Score calculation with multiple severity levels (bottoms out at 0) ───
  it('calculates score correctly with mixed severity issues', async () => {
    const dir = await makeTmp({
      'deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: score-test
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: app
          image: app:1.0
          securityContext:
            privileged: true
`,
    });
    try {
      const result = await scanK8s(dir);
      // high: privileged(1) + runAsRoot(1) + hostNetwork(1) = 3 high
      // medium: hostPID(1) + noLimits(1) = 2 medium
      // low: noRequests(1) + noLiveness(1) + noReadiness(1) = 3 low
      // score = max(0, 100 - 3*25 - 2*10 - 3*3) = max(0, -4) = 0
      assert.equal(result.score, 0);
      assert.ok(result.summary.highRiskIssues >= 3);
      assert.ok(result.summary.mediumRiskIssues >= 2);
      assert.ok(result.summary.lowRiskIssues >= 3);
    } finally {
      await fs.remove(dir);
    }
  });
});
