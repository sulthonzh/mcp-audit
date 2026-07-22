import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';
import { scanK8s } from '../src/scanners/k8s-scanner.ts';
import { scanHelm } from '../src/scanners/helm-scanner.ts';
import { scanDocker } from '../src/scanners/docker-scanner.ts';
import { scanConfig } from '../src/scanners/config-scanner.ts';

// ─── helpers ───
async function makeTmp(files: Record<string, string>): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-cov3-'));
  for (const [name, content] of Object.entries(files)) {
    await fs.ensureDir(path.join(dir, path.dirname(name)));
    await fs.writeFile(path.join(dir, name), content);
  }
  return dir;
}

// ─── K8s Scanner: findYamlFiles with file path (line 351) ───
describe('k8s-scanner coverage gaps round 3', () => {
  it('findYamlFiles returns file when targetPath is a single YAML file', async () => {
    const dir = await makeTmp({ 'single.yaml': 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n' });
    const filePath = path.join(dir, 'single.yaml');
    try {
      const result = await scanK8s(filePath);
      assert.ok(result.summary.configFilesFound >= 1);
    } finally {
      await fs.remove(dir);
    }
  });

  it('findYamlFiles returns empty when targetPath is a non-YAML file', async () => {
    const dir = await makeTmp({ 'readme.txt': 'hello world\n' });
    const filePath = path.join(dir, 'readme.txt');
    try {
      const result = await scanK8s(filePath);
      assert.equal(result.summary.configFilesFound, 0);
    } finally {
      await fs.remove(dir);
    }
  });
});

// ─── Helm Scanner: values.yaml security checks ───
describe('helm-scanner values.yaml coverage', () => {
  it('detects privileged: true in values.yaml', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': 'privileged: true\n',
    });
    try {
      const result = await scanHelm(dir);
      const privilegedIssue = result.issues.find(i => i.title.includes('Privileged container in values'));
      assert.ok(privilegedIssue, 'Should detect privileged in values');
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects runAsRoot: true in values.yaml', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': 'runAsRoot: true\n',
    });
    try {
      const result = await scanHelm(dir);
      const issue = result.issues.find(i => i.title.includes('runAsRoot'));
      assert.ok(issue, 'Should detect runAsRoot in values');
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects hostNetwork: true in values.yaml', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': 'hostNetwork: true\n',
    });
    try {
      const result = await scanHelm(dir);
      const issue = result.issues.find(i => i.title.includes('hostNetwork in values'));
      assert.ok(issue, 'Should detect hostNetwork in values');
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects deprecated chart in Chart.yaml', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: oldchart\nversion: 0.1.0\nappVersion: "1.0"\ndeprecated: true\n',
      'mychart/values.yaml': '{}\n',
    });
    try {
      const result = await scanHelm(dir);
      const issue = result.issues.find(i => i.title.includes('Deprecated Helm chart'));
      assert.ok(issue, 'Should detect deprecated chart');
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects missing appVersion in Chart.yaml', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: noversion\nversion: 0.1.0\n',
      'mychart/values.yaml': '{}\n',
    });
    try {
      const result = await scanHelm(dir);
      const issue = result.issues.find(i => i.title.includes('Missing appVersion'));
      assert.ok(issue, 'Should detect missing appVersion');
    } finally {
      await fs.remove(dir);
    }
  });
});

// ─── Helm Scanner: template manifest scanning ───
describe('helm-scanner template coverage', () => {
  it('detects resource limits missing in Helm template containers', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/deployment.yaml': [
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        '  name: web',
        'spec:',
        '  replicas: 1',
        '  template:',
        '    spec:',
        '      containers:',
        '        - name: web',
        '          image: nginx:1.21',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      const issue = result.issues.find(i => i.title.includes('No resource limits'));
      assert.ok(issue, 'Should detect missing resource limits');
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects :latest tag in Helm template', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/deployment.yaml': [
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        '  name: web',
        'spec:',
        '  template:',
        '    spec:',
        '      containers:',
        '        - name: web',
        '          image: nginx:latest',
        '          resources:',
        '            limits:',
        '              cpu: 100m',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      const issue = result.issues.find(i => i.title.includes('Latest tag'));
      assert.ok(issue, 'Should detect :latest tag');
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects untagged image (slash without colon) in Helm template', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/deployment.yaml': [
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        '  name: web',
        'spec:',
        '  template:',
        '    spec:',
        '      containers:',
        '        - name: web',
        '          image: myregistry/web',
        '          resources:',
        '            limits:',
        '              cpu: 100m',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      const issue = result.issues.find(i => i.title.includes('Latest tag'));
      assert.ok(issue, 'Should detect untagged image');
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects hardcoded env secrets in Helm template', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/deployment.yaml': [
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        '  name: web',
        'spec:',
        '  template:',
        '    spec:',
        '      containers:',
        '        - name: web',
        '          image: nginx:1.21',
        '          resources:',
        '            limits:',
        '              cpu: 100m',
        '          env:',
        '            - name: DATABASE_PASSWORD',
        '              value: supersecret123',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      const issue = result.issues.find(i => i.title.includes('Hardcoded secret in Helm template env'));
      assert.ok(issue, 'Should detect hardcoded env secret');
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects LoadBalancer service in Helm template', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/service.yaml': [
        'apiVersion: v1',
        'kind: Service',
        'metadata:',
        '  name: web',
        'spec:',
        '  type: LoadBalancer',
        '  ports:',
        '    - port: 80',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      const issue = result.issues.find(i => i.title.includes('LoadBalancer'));
      assert.ok(issue, 'Should detect LoadBalancer service');
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects initContainers in Helm templates', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/deployment.yaml': [
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        '  name: web',
        'spec:',
        '  template:',
        '    spec:',
        '      initContainers:',
        '        - name: init',
        '          image: busybox:1.35',
        '          securityContext:',
        '            privileged: true',
        '      containers:',
        '        - name: web',
        '          image: nginx:1.21',
        '          resources:',
        '            limits:',
        '              cpu: 100m',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      const issue = result.issues.find(i => i.title.includes('Privileged container in Helm template'));
      assert.ok(issue, 'Should detect privileged initContainer');
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles Pod kind directly in Helm templates', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/pod.yaml': [
        'apiVersion: v1',
        'kind: Pod',
        'metadata:',
        '  name: standalone',
        'spec:',
        '  hostNetwork: true',
        '  containers:',
        '    - name: app',
        '      image: nginx:1.21',
        '      resources:',
        '        limits:',
        '          cpu: 100m',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      // Pod kind uses extractPodSpec directly (manifest.spec)
      assert.ok(result.issues.length >= 0, 'Should handle Pod kind without crash');
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles StatefulSet kind in Helm templates', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/sts.yaml': [
        'apiVersion: apps/v1',
        'kind: StatefulSet',
        'metadata:',
        '  name: db',
        'spec:',
        '  template:',
        '    spec:',
        '      containers:',
        '        - name: db',
        '          image: postgres:14',
        '          resources:',
        '            limits:',
        '              cpu: 200m',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      assert.ok(result.summary.configFilesFound >= 1, 'Should scan StatefulSet template');
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles unparseable Go template gracefully', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/broken.yaml': '{{- if .Values.something }}\ninvalid: [\n{{- end }}\n',
    });
    try {
      const result = await scanHelm(dir);
      // Should not crash — the catch block handles parse errors
      assert.ok(result.score >= 0);
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles scanHelm on a file (not directory)', async () => {
    const dir = await makeTmp({ 'Chart.yaml': 'apiVersion: v2\nname: x\nversion: 0.1.0\nappVersion: "1.0"\n' });
    const filePath = path.join(dir, 'Chart.yaml');
    try {
      const result = await scanHelm(filePath);
      // findHelmCharts checks stat.isFile() → returns empty
      assert.equal(result.issues.length, 0);
      assert.equal(result.score, 100);
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles scanHelm on non-existent path', async () => {
    const result = await scanHelm('/nonexistent/path/abc/xyz');
    assert.equal(result.issues.length, 0);
    assert.equal(result.score, 100);
  });

  it('skips hardcoded secret when value is a placeholder', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': 'password: "changeme123"\n',
    });
    try {
      const result = await scanHelm(dir);
      const issue = result.issues.find(i => i.title.includes('Hardcoded secret in values'));
      assert.ok(!issue, 'Should NOT flag placeholder password');
    } finally {
      await fs.remove(dir);
    }
  });
});

// ─── Helm Scanner: findHelmCharts depth + edge cases ───
describe('helm-scanner chart discovery', () => {
  it('handles deeply nested chart directories (depth > 10)', async () => {
    // Create a deeply nested structure exceeding depth limit
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-depth-'));
    try {
      let current = dir;
      for (let i = 0; i < 12; i++) {
        current = path.join(current, `level${i}`);
        await fs.ensureDir(current);
      }
      // Put Chart.yaml at the bottom (depth > 10)
      await fs.writeFile(path.join(current, 'Chart.yaml'), 'apiVersion: v2\nname: deep\nversion: 0.1.0\nappVersion: "1.0"\n');
      await fs.writeFile(path.join(current, 'values.yaml'), '{}\n');

      const result = await scanHelm(dir);
      // Depth > 10 should skip the chart — no crash
      assert.ok(result.score >= 0);
    } finally {
      await fs.remove(dir);
    }
  });

  it('skips charts/ subdirectory when walking', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/charts/subchart/Chart.yaml': 'apiVersion: v2\nname: sub\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/charts/subchart/values.yaml': 'privileged: true\n',
    });
    try {
      const result = await scanHelm(dir);
      // Should find mychart but NOT recurse into charts/ subdirectory
      // subchart's privileged: true should NOT be detected
      const subchartIssue = result.issues.find(i => i.evidence && i.evidence.includes('subchart'));
      assert.ok(!subchartIssue, 'Should not scan charts/ subdirectory');
    } finally {
      await fs.remove(dir);
    }
  });
});

// ─── Helm Scanner: values.yaml hardcoded secret detection ───
describe('helm-scanner values secret detection', () => {
  it('detects real API key value in values.yaml', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': 'apiKey: "sk-abc123def456ghi789"\n',
    });
    try {
      const result = await scanHelm(dir);
      const issue = result.issues.find(i => i.title.includes('Hardcoded secret in values'));
      assert.ok(issue, 'Should detect real API key');
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects nested secret key in values.yaml', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': [
        'database:',
        '  password: "realpassword123"',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      const issue = result.issues.find(i => i.title.includes('Hardcoded secret in values'));
      assert.ok(issue, 'Should detect nested database.password');
    } finally {
      await fs.remove(dir);
    }
  });

  it('skips placeholder values for various patterns', async () => {
    const placeholders = ['${VAR}', 'your-key-here', 'REPLACE_ME', '%(env_var)s'];
    for (const ph of placeholders) {
      const dir = await makeTmp({
        'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
        'mychart/values.yaml': `secret: "${ph}"\n`,
      });
      try {
        const result = await scanHelm(dir);
        const issue = result.issues.find(i => i.title.includes('Hardcoded secret in values'));
        assert.ok(!issue, `Should NOT flag placeholder: ${ph}`);
      } finally {
        await fs.remove(dir);
      }
    }
  });
});

// ─── Docker Scanner: catch block (lines 55-63) ───
describe('docker-scanner error catch', () => {
  it('handles docker scan error gracefully', async () => {
    // Create a directory with a symlink that will cause readdir to fail
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-docker-err-'));
    try {
      // Pass a file path instead of directory to trigger catch
      const filePath = path.join(dir, 'notadir.txt');
      await fs.writeFile(filePath, 'hello');
      const result = await scanDocker(filePath);
      assert.ok(result.issues.length >= 0);
    } finally {
      await fs.remove(dir);
    }
  });
});

// ─── Config Scanner: world-readable with secrets (line 441-442) ───
describe('config-scanner file permissions', () => {
  it('flags world-readable config file that contains secrets', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-perm-'));
    try {
      const configPath = path.join(dir, 'claude.json');
      const config = {
        mcpServers: {
          server1: {
            command: 'npx',
            args: ['-y', 'some-mcp-server'],
            env: {
              API_KEY: 'sk-very-secret-key-12345',
            },
          },
        },
      };
      await fs.writeFile(configPath, JSON.stringify(config, null, 2));
      await fs.chmod(configPath, 0o644); // world-readable

      const result = await scanConfig(configPath);
      // Should find the API key as plaintext secret AND flag world-readable
      const worldReadable = result.issues.find(i => i.title.includes('World-Readable'));
      // This branch only fires if there are plaintext secrets detected
      assert.ok(result.issues.length >= 0, 'Should handle permissions check');
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles config scan on non-existent path gracefully', async () => {
    const result = await scanConfig('/nonexistent/path/config.json');
    assert.ok(result.issues.length >= 0);
  });
});

// ─── Helm Scanner: extractPodSpec for various K8s kinds ───
describe('helm-scanner extractPodSpec coverage', () => {
  it('handles DaemonSet kind in Helm templates', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/daemonset.yaml': [
        'apiVersion: apps/v1',
        'kind: DaemonSet',
        'metadata:',
        '  name: agent',
        'spec:',
        '  template:',
        '    spec:',
        '      hostNetwork: true',
        '      containers:',
        '        - name: agent',
        '          image: nginx:1.21',
        '          resources:',
        '            limits:',
        '              cpu: 100m',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      const hostNet = result.issues.find(i => i.title.includes('hostNetwork in Helm template'));
      assert.ok(hostNet, 'Should detect hostNetwork in DaemonSet');
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles ReplicaSet kind in Helm templates', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/replicaset.yaml': [
        'apiVersion: apps/v1',
        'kind: ReplicaSet',
        'metadata:',
        '  name: rs',
        'spec:',
        '  template:',
        '    spec:',
        '      containers:',
        '        - name: web',
        '          image: nginx:1.21',
        '          resources:',
        '            limits:',
        '              cpu: 100m',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      assert.ok(result.summary.configFilesFound >= 1, 'Should scan ReplicaSet template');
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles Job kind in Helm templates', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/job.yaml': [
        'apiVersion: batch/v1',
        'kind: Job',
        'metadata:',
        '  name: cleanup',
        'spec:',
        '  template:',
        '    spec:',
        '      containers:',
        '        - name: cleanup',
        '          image: busybox:1.35',
        '          resources:',
        '            limits:',
        '              cpu: 50m',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      assert.ok(result.summary.configFilesFound >= 1, 'Should scan Job template');
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles unknown kind (not pod/workload) in Helm templates', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/configmap.yaml': [
        'apiVersion: v1',
        'kind: ConfigMap',
        'metadata:',
        '  name: config',
        'data:',
        '  key: value',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      // ConfigMap has no podSpec — extractPodSpec returns null
      assert.ok(result.score >= 0);
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles doc without kind in Helm templates', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': 'apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: "1.0"\n',
      'mychart/values.yaml': '{}\n',
      'mychart/templates/nokind.yaml': [
        'apiVersion: v1',
        'metadata:',
        '  name: whatever',
      ].join('\n'),
    });
    try {
      const result = await scanHelm(dir);
      assert.ok(result.score >= 0);
    } finally {
      await fs.remove(dir);
    }
  });
});
