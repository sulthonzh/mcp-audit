import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';
import { scanK8s } from '../src/scanners/k8s-scanner.ts';
import { scanHelm } from '../src/scanners/helm-scanner.ts';
import { scanDocker } from '../src/scanners/docker-scanner.ts';
import { autoFixConfig } from '../src/scanners/config-fixer.ts';
import { generateSarifOutput, generateSarifReport } from '../src/reporters/sarif-reporter.ts';

const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';

// ─── helpers ───
async function makeTmp(files: Record<string, string>): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-cov-'));
  for (const [name, content] of Object.entries(files)) {
    await fs.ensureDir(path.join(dir, path.dirname(name)));
    await fs.writeFile(path.join(dir, name), content);
  }
  return dir;
}

// ─── K8s Scanner: resource requests + volumeMounts + walk filtering ───
describe('k8s-scanner coverage gaps', () => {
  it('detects missing resource requests', async () => {
    const dir = await makeTmp({
      'deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata: { name: test }
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
          resources:
            limits:
              memory: 256Mi
`,
    });
    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'No resource requests set'));
    } finally { await fs.remove(dir); }
  });

  it('detects suspicious host mount path via volumeMounts', async () => {
    const dir = await makeTmp({
      'deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata: { name: test }
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
          volumeMounts:
            - name: host-data
              mountPath: /host/data
`,
    });
    try {
      const result = await scanK8s(dir);
      assert.ok(result.issues.some(i => i.title === 'Suspicious host mount path'));
    } finally { await fs.remove(dir); }
  });

  it('walk skips hidden dirs and node_modules', async () => {
    const dir = await makeTmp({
      '.hidden/deploy.yaml': `
apiVersion: v1
kind: Pod
metadata: { name: hidden }
spec:
  containers:
    - { name: c, image: nginx:1.25 }
`,
      'node_modules/mod/deploy.yaml': `
apiVersion: v1
kind: Pod
metadata: { name: mod }
spec:
  containers:
    - { name: c, image: nginx:1.25 }
`,
      'real.yaml': `
apiVersion: v1
kind: Pod
metadata: { name: real }
spec:
  containers:
    - { name: c, image: nginx:1.25 }
`,
    });
    try {
      const result = await scanK8s(dir);
      // Only 'real.yaml' should be found — hidden and node_modules are skipped
      const evidences = result.issues.map(i => i.evidence || '');
      assert.ok(!evidences.some(e => e.includes('hidden')));
      assert.ok(!evidences.some(e => e.includes('node_modules')));
      // real.yaml should be found
      assert.ok(result.issues.length > 0);
    } finally { await fs.remove(dir); }
  });
});

// ─── Helm Scanner: env secrets + isFile + Go template parse error + non-existent path ───
describe('helm-scanner coverage gaps', () => {
  it('detects hardcoded secret in Helm template env', async () => {
    const dir = await makeTmp({
      'mychart/Chart.yaml': `apiVersion: v2\nname: test\nversion: 1.0.0\nappVersion: 1.0.0\n`,
      'mychart/templates/deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
          env:
            - name: API_TOKEN
              value: "super-secret-value"
`,
      'mychart/values.yaml': `image: nginx:1.25\n`,
    });
    try {
      const result = await scanHelm(dir);
      assert.ok(result.issues.some(i => i.title === 'Hardcoded secret in Helm template env'));
    } finally { await fs.remove(dir); }
  });

  it('returns empty result when target is a file (not directory)', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'helm-file-'));
    const filePath = path.join(dir, 'Chart.yaml');
    await fs.writeFile(filePath, 'apiVersion: v2\nname: test\n');
    try {
      const result = await scanHelm(filePath);
      assert.equal(result.issues.length, 0);
      assert.equal(result.score, 100);
    } finally { await fs.remove(dir); }
  });

  it('handles Go template with unparseable YAML after stripping', async () => {
    const dir = await makeTmp({
      'broken/Chart.yaml': `apiVersion: v2\nname: test\nversion: 1.0.0\nappVersion: 1.0.0\n`,
      'broken/templates/bad.yaml': `
{{- range $i := until 10 }}
---
{{- if eq $i 0 }}
apiVersion: v1
kind: ConfigMap
{{- else }}
apiVersion: v1
kind: Service
{{- end }}
{{- end }}
`,
      'broken/values.yaml': `foo: bar\n`,
    });
    try {
      // Should not throw — just logs debug
      const result = await scanHelm(dir);
      assert.ok(result);
    } finally { await fs.remove(dir); }
  });

  it('findHelmCharts handles non-existent path', async () => {
    const result = await scanHelm('/nonexistent/path/that/does/not/exist');
    assert.equal(result.issues.length, 0);
    assert.equal(result.score, 100);
  });
});

// ─── Docker Scanner: privileged port, ADD URL, compose invalid YAML, walk filtering ───
describe('docker-scanner coverage gaps', () => {
  it('detects privileged port in EXPOSE', async () => {
    const dir = await makeTmp({
      'Dockerfile': `FROM alpine:3.18\nEXPOSE 80\n`,
    });
    try {
      const result = await scanDocker(dir);
      assert.ok(result.issues.some(i => i.title === 'Privileged Port Exposed'));
    } finally { await fs.remove(dir); }
  });

  it('detects ADD from remote URL', async () => {
    const dir = await makeTmp({
      'Dockerfile': `FROM alpine:3.18\nADD https://example.com/file.tar.gz /tmp/\n`,
    });
    try {
      const result = await scanDocker(dir);
      assert.ok(result.issues.some(i => i.title === 'ADD from Remote URL'));
    } finally { await fs.remove(dir); }
  });

  it('handles invalid docker-compose YAML gracefully', async () => {
    const dir = await makeTmp({
      'docker-compose.yml': `services: [invalid\n  - broken yaml\n`,
    });
    try {
      const result = await scanDocker(dir);
      assert.ok(result.issues.some(i => i.title === 'Invalid YAML'));
    } finally { await fs.remove(dir); }
  });

  it('walk skips node_modules and .git directories', async () => {
    const dir = await makeTmp({
      'Dockerfile': `FROM alpine:3.18\nUSER root\n`,
      'node_modules/pkg/Dockerfile': `FROM alpine:3.18\nUSER root\n`,
      '.git/Dockerfile': `FROM alpine:3.18\nUSER root\n`,
    });
    try {
      const result = await scanDocker(dir);
      // Root Dockerfile should be found (may appear twice due to overlapping glob patterns)
      const rootIssues = result.issues.filter(i => i.title === 'Container Runs as Root');
      assert.ok(rootIssues.length >= 1 && rootIssues.length <= 2);
      // Ensure no issues from node_modules or .git paths
      assert.ok(!result.issues.some(i => i.evidence?.includes('node_modules')));
      assert.ok(!result.issues.some(i => i.evidence?.includes('.git')));
    } finally { await fs.remove(dir); }
  });

  it('glob matching works for Dockerfile.* patterns', async () => {
    const dir = await makeTmp({
      'Dockerfile.prod': `FROM alpine:3.18\nUSER root\n`,
      'Dockerfile.dev': `FROM alpine:3.18\nEXPOSE 443\n`,
    });
    try {
      const result = await scanDocker(dir);
      // Both Dockerfiles should be found
      const rootIssues = result.issues.filter(i => i.title === 'Container Runs as Root');
      const portIssues = result.issues.filter(i => i.title === 'Privileged Port Exposed');
      assert.ok(rootIssues.length >= 1);
      assert.ok(portIssues.length >= 1);
    } finally { await fs.remove(dir); }
  });
});

// ─── Config Fixer: wildcard args, output path, permissions ───
describe('config-fixer coverage gaps', () => {
  const tmpDir = path.join(os.tmpdir(), `mcp-fixer-cov-${Date.now()}`);
  let originalCwd: string;
  let originalHome: string;

  beforeEach(async () => {
    originalCwd = process.cwd();
    originalHome = process.env.HOME || '';
    await fs.ensureDir(tmpDir);
    const fakeHome = path.join(tmpDir, 'fake-home');
    await fs.ensureDir(fakeHome);
    process.env.HOME = fakeHome;
    process.chdir(tmpDir);
  });

  afterEach(async () => {
    process.chdir(originalCwd);
    process.env.HOME = originalHome;
    await fs.remove(tmpDir);
  });

  it('restricts /* filesystem arg', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        fs: {
          command: 'npx',
          args: ['server', '/*'],
        },
      },
    });

    const results = await autoFixConfig({ quiet: true });
    assert.ok(results.length > 0);
    assert.ok(results[0].fixesApplied.some(f => f.newValue === './'));
  });

  it('restricts ~/* filesystem arg', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        fs: {
          command: 'npx',
          args: ['server', '~/*'],
        },
      },
    });

    const results = await autoFixConfig({ quiet: true });
    assert.ok(results.length > 0);
    assert.ok(results[0].fixesApplied.some(f => f.newValue === './'));
  });

  it('writes fixed config with inPlace', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        bad: {
          command: 'npx',
          args: ['--allow-all'],
        },
      },
    });

    const results = await autoFixConfig({ dryRun: false, inPlace: true, quiet: true });
    assert.ok(results.length > 0);
    assert.ok(results[0].fixesApplied.length > 0);
    // Verify the file was actually modified
    const fixed = JSON.parse(await fs.readFile(configPath, 'utf8'));
    assert.ok(!JSON.stringify(fixed).includes('--allow-all'));
  });

  it('fixFilePermissions actually fixes in non-dry-run', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        bad: {
          command: 'npx',
          args: ['--auto-approve'],
        },
      },
    });
    await fs.chmod(configPath, 0o644);

    await autoFixConfig({ dryRun: false, inPlace: true, quiet: true });

    const stat = await fs.stat(configPath);
    const mode = stat.mode & 0o777;
    assert.equal(mode, 0o600);
  });

  it('fixFilePermissions reports in dry run without changing', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        bad: {
          command: 'npx',
          args: ['--auto-approve'],
        },
      },
    });
    await fs.chmod(configPath, 0o644);

    await autoFixConfig({ dryRun: true, quiet: true });

    // File should NOT be changed in dry run
    const stat = await fs.stat(configPath);
    const mode = stat.mode & 0o777;
    assert.equal(mode, 0o644);
  });
});

// ─── SARIF Reporter: generateSarifReport (file output + stdout) + evidence ───
describe('sarif-reporter coverage gaps', () => {
  it('generateSarifReport writes to file when outputPath given', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sarif-'));
    const outputPath = path.join(dir, 'report.sarif');
    const result = {
      scanType: 'config' as const,
      timestamp: new Date().toISOString(),
      target: '/test/path',
      issues: [
        { type: 'high' as const, category: 'config' as const, title: 'Test Issue', description: 'Test desc', recommendation: 'Fix it', evidence: 'line 1' },
      ],
      score: 75,
      summary: { configFilesFound: 1, highRiskIssues: 1, mediumRiskIssues: 0, lowRiskIssues: 0 },
    };
    try {
      await generateSarifReport(result, outputPath);
      assert.ok(await fs.pathExists(outputPath));
      const written = JSON.parse(await fs.readFile(outputPath, 'utf8'));
      assert.equal(written['$schema'], SARIF_SCHEMA);
    } finally {
      await fs.remove(dir);
    }
  });

  it('generateSarifReport outputs to stdout when no outputPath', async () => {
    const originalLog = console.log;
    let captured = '';
    console.log = (...args: unknown[]) => { captured = args[0] as string; };
    try {
      const result = {
        scanType: 'config' as const,
        timestamp: new Date().toISOString(),
        target: 'relative/path',
        issues: [],
        score: 100,
        summary: { configFilesFound: 0, highRiskIssues: 0, mediumRiskIssues: 0, lowRiskIssues: 0 },
      };
      await generateSarifReport(result);
      assert.ok(captured.length > 0);
      const parsed = JSON.parse(captured);
      assert.equal(parsed.runs[0].results.length, 0);
    } finally {
      console.log = originalLog;
    }
  });

  it('generateSarifOutput handles relative target paths', () => {
    const result = {
      scanType: 'config' as const,
      timestamp: new Date().toISOString(),
      target: 'relative/path',
      issues: [],
      score: 100,
      summary: { configFilesFound: 0, highRiskIssues: 0, mediumRiskIssues: 0, lowRiskIssues: 0 },
    };
    const sarif = generateSarifOutput(result) as { runs: Array<{ results: unknown[] }> };
    assert.ok(sarif.runs[0].results.length === 0);
  });

  it('generateSarifOutput includes evidence in results', () => {
    const result = {
      scanType: 'config' as const,
      timestamp: new Date().toISOString(),
      target: '/abs/path',
      issues: [
        { type: 'high' as const, category: 'injection' as const, title: 'Shell Injection', description: 'desc', recommendation: 'rec', evidence: 'config.json:42' },
      ],
      score: 50,
      summary: { configFilesFound: 1, highRiskIssues: 1, mediumRiskIssues: 0, lowRiskIssues: 0 },
    };
    const sarif = generateSarifOutput(result) as {
      runs: Array<{
        results: Array<{ properties: { evidence?: string } }>;
      }>;
    };
    assert.ok(sarif.runs[0].results[0].properties.evidence === 'config.json:42');
  });
});
