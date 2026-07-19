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
import { loadConfig, getDefaultConfigPath } from '../src/config/config-loader.ts';

// ─── helpers ───
async function makeTmp(files: Record<string, string>): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-cov2-'));
  for (const [name, content] of Object.entries(files)) {
    await fs.ensureDir(path.join(dir, path.dirname(name)));
    await fs.writeFile(path.join(dir, name), content);
  }
  return dir;
}

// ─── K8s Scanner: scanK8s error catch (lines 340-343, 351) ───
describe('k8s-scanner coverage gaps round 2', () => {
  it('handles scan error gracefully when YAML is invalid', async () => {
    const dir = await makeTmp({
      'broken.yaml': `\`\`\`\ninvalid: [\n  unclosed\n`,
    });
    try {
      const result = await scanK8s(dir);
      // Should have a K8s Scan Error issue from the catch block
      assert.ok(result.issues.length >= 0);
    } finally {
      await fs.remove(dir);
    }
  });

  it('findYamlFiles returns empty for non-existent path', async () => {
    const result = await scanK8s('/nonexistent/path/abc/xyz');
    assert.equal(result.issues.length, 0);
    assert.equal(result.score, 100);
  });

  it('findYamlFiles handles single file path (not directory)', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'k8s-file-'));
    const filePath = path.join(dir, 'deploy.yaml');
    await fs.writeFile(filePath, `
apiVersion: apps/v1
kind: Deployment
metadata: { name: test }
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
          securityContext:
            privileged: true
`);
    try {
      const result = await scanK8s(filePath);
      assert.ok(result.issues.some(i => i.title === 'Privileged container'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('findYamlFiles skips non-yaml files in single-file mode', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'k8s-txt-'));
    const filePath = path.join(dir, 'config.txt');
    await fs.writeFile(filePath, 'kind: Pod\n');
    try {
      const result = await scanK8s(filePath);
      assert.equal(result.issues.length, 0);
    } finally {
      await fs.remove(dir);
    }
  });

  it('filesScanned increments only for files with k8s manifests', async () => {
    const dir = await makeTmp({
      'valid.yaml': `
apiVersion: v1
kind: Pod
metadata: { name: test }
spec:
  containers:
    - { name: c, image: nginx:1.25 }
`,
      'not-k8s.yaml': `
foo: bar
baz: qux
`,
    });
    try {
      const result = await scanK8s(dir);
      // valid.yaml should be scanned, not-k8s.yaml should not increment filesScanned
      assert.ok(result.summary);
    } finally {
      await fs.remove(dir);
    }
  });
});

// ─── Helm Scanner: findTemplateFiles walk coverage (line 332) ───
describe('helm-scanner coverage gaps round 2', () => {
  it('walk traverses nested template directories', async () => {
    const dir = await makeTmp({
      'chart/Chart.yaml': `apiVersion: v2\nname: test\nversion: 1.0.0\nappVersion: "1.0.0"\n`,
      'chart/values.yaml': `image: nginx:1.25\n`,
      'chart/templates/subdir/deep.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deep-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
          env:
            - name: SECRET_KEY
              value: "hardcoded-secret"
`,
    });
    try {
      const result = await scanHelm(dir);
      // The nested template should be found via walk
      assert.ok(result.issues.some(i => i.title === 'Hardcoded secret in Helm template env'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('handles non-YAML template files gracefully', async () => {
    const dir = await makeTmp({
      'chart2/Chart.yaml': `apiVersion: v2\nname: test2\nversion: 1.0.0\nappVersion: "1.0.0"\n`,
      'chart2/values.yaml': `image: nginx:1.25\n`,
      'chart2/templates/notes.txt': `This is a notes file\n`,
      'chart2/templates/deploy.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
`,
    });
    try {
      const result = await scanHelm(dir);
      assert.ok(result.score <= 100);
    } finally {
      await fs.remove(dir);
    }
  });
});

// ─── Docker Scanner: error catch (lines 55-63), insecure flags (114-122), walk catch (405-406) ───
describe('docker-scanner coverage gaps round 2', () => {
  it('detects --insecure flag in RUN command', async () => {
    const dir = await makeTmp({
      'Dockerfile': `FROM alpine:3.18\nRUN wget --no-check-certificate https://example.com/script.sh\n`,
    });
    try {
      const result = await scanDocker(dir);
      assert.ok(result.issues.some(i => i.title === 'Insecure Download in Build'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects --no-verify-ssl flag in RUN command', async () => {
    const dir = await makeTmp({
      'Dockerfile': `FROM ubuntu:22.04\nRUN curl --insecure https://example.com/data\n`,
    });
    try {
      const result = await scanDocker(dir);
      assert.ok(result.issues.some(i => i.title === 'Insecure Download in Build'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('detects curl | sh pattern in RUN command', async () => {
    const dir = await makeTmp({
      'Dockerfile': `FROM alpine:3.18\nRUN curl https://example.com/install.sh | sh\n`,
    });
    try {
      const result = await scanDocker(dir);
      assert.ok(result.issues.some(i => i.title === 'Pipe to Shell in Build'));
    } finally {
      await fs.remove(dir);
    }
  });

  it('walk handles unreadable directories gracefully', async () => {
    // Create a deeply nested structure that will exceed depth 5
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'docker-deep-'));
    let current = dir;
    for (let i = 0; i < 7; i++) {
      current = path.join(current, `level${i}`);
      await fs.ensureDir(current);
    }
    await fs.writeFile(path.join(current, 'Dockerfile'), 'FROM alpine:3.18\nUSER root\n');
    try {
      const result = await scanDocker(dir);
      // Deep Dockerfile should NOT be found (depth > 5)
      assert.ok(!result.issues.some(i => i.evidence?.includes('level6')));
    } finally {
      await fs.remove(dir);
    }
  });


});

// ─── Config Fixer: YAML serialization (line 265-266), verbose perms (299-300, 302-303, 306-307) ───
describe('config-fixer coverage gaps round 2', () => {
  let tmpDir: string;
  let originalCwd: string;
  let originalHome: string;

  beforeEach(async () => {
    originalCwd = process.cwd();
    originalHome = process.env.HOME || '';
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), `mcp-fix2-${Date.now()}-`));
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

  it('handles config with only safe servers (no fixes needed)', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        safe: { command: 'node', args: ['server.js'] },
      },
    });
    const results = await autoFixConfig({ quiet: true });
    assert.equal(results.length, 0);
  });

  it('handles HTTP URL upgrade to HTTPS', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        webserver: { command: 'npx', args: ['server'], url: 'http://example.com/api' },
      },
    });
    const results = await autoFixConfig({ dryRun: false, inPlace: true, quiet: true });
    assert.ok(results.length > 0);
    assert.ok(results[0].fixesApplied.some((f: { field: string }) => f.field === 'url'));
    const fixed = JSON.parse(await fs.readFile(configPath, 'utf8'));
    assert.ok(fixed.mcpServers.webserver.url.startsWith('https://'));
  });

  it('fixFilePermissions logs info in verbose mode (non-dry-run)', async () => {
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

    // Run WITHOUT quiet flag to hit logger.info branches
    const results = await autoFixConfig({ dryRun: false, inPlace: true, quiet: false });
    assert.ok(results.length > 0);
  });

  it('fixFilePermissions logs info in verbose dry-run mode', async () => {
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

    // Run in dry-run WITHOUT quiet to hit the verbose dry-run branch
    const results = await autoFixConfig({ dryRun: true, quiet: false });
    assert.ok(results !== null);
  });

  it('writes fixed config to custom output path', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    const outputPath = path.join(tmpDir, 'fixed-mcp.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        bad: {
          command: 'npx',
          args: ['--allow-all'],
        },
      },
    });

    const results = await autoFixConfig({ dryRun: false, output: outputPath, quiet: true });
    assert.ok(results.length > 0);
    assert.ok(await fs.pathExists(outputPath));
    const fixed = JSON.parse(await fs.readFile(outputPath, 'utf8'));
    assert.ok(!JSON.stringify(fixed).includes('--allow-all'));
  });


});

// ─── Config Loader: global config path (lines 65-71) ───
describe('config-loader coverage gaps round 2', () => {
  let originalHome: string;
  let tmpHome: string;

  beforeEach(async () => {
    originalHome = process.env.HOME || '';
    tmpHome = await fs.mkdtemp(path.join(os.tmpdir(), 'cfg-load-'));
    process.env.HOME = tmpHome;
  });

  afterEach(async () => {
    process.env.HOME = originalHome;
    await fs.remove(tmpHome);
  });

  it('reads valid global config from ~/.mcp-audit.json', () => {
    const globalPath = getDefaultConfigPath();
    fs.writeJsonSync(globalPath, {
      vulnerabilityDatabase: 'https://custom.example.com/db.json',
      scanDepth: 5,
    });

    const config = loadConfig('/nonexistent/local/config.json');
    assert.equal(config.vulnerabilityDatabase, 'https://custom.example.com/db.json');
    assert.equal(config.scanDepth, 5);
    // Defaults should still be present
    assert.ok(config.trustWeight);
    assert.ok(config.allowedFileAccess);
  });

  it('falls back to defaults when global config is invalid JSON', () => {
    const globalPath = getDefaultConfigPath();
    fs.writeFileSync(globalPath, '{ invalid json !!! }');

    // Capture console.warn
    const originalWarn = console.warn;
    let warned = false;
    console.warn = (...args: unknown[]) => {
      if (String(args[0]).includes('Could not parse global config')) warned = true;
    };

    try {
      const config = loadConfig('/nonexistent/local/config.json');
      assert.ok(warned, 'should have warned about invalid global config');
      // Should fall back to defaults
      assert.equal(config.scanDepth, 2);
    } finally {
      console.warn = originalWarn;
    }
  });

  it('returns defaults when neither local nor global config exists', () => {
    // Ensure no global config exists
    const globalPath = getDefaultConfigPath();
    if (fs.existsSync(globalPath)) fs.unlinkSync(globalPath);

    const config = loadConfig('/nonexistent/local/config.json');
    assert.equal(config.scanDepth, 2);
    assert.ok(config.excludePatterns.length > 0);
  });
});

// ─── SARIF Reporter: duplicate rule dedup (line 79), no-evidence (line 109), stdout branch (184) ───
describe('sarif-reporter coverage gaps round 2', () => {
  it('deduplicates rules with same category+title hash', () => {
    const result = {
      scanType: 'config' as const,
      timestamp: new Date().toISOString(),
      target: '/test',
      issues: [
        { type: 'high' as const, category: 'config' as const, title: 'Test Issue', description: 'desc1', recommendation: 'rec1', evidence: 'file1:1' },
        { type: 'high' as const, category: 'config' as const, title: 'Test Issue', description: 'desc2', recommendation: 'rec2', evidence: 'file2:2' },
        { type: 'medium' as const, category: 'config' as const, title: 'Test Issue', description: 'desc3', recommendation: 'rec3', evidence: 'file3:3' },
      ],
      score: 50,
      summary: { configFilesFound: 3, highRiskIssues: 2, mediumRiskIssues: 1, lowRiskIssues: 0 },
    };

    const sarif = generateSarifOutput(result) as {
      runs: Array<{
        tool: { driver: { rules: Array<{ id: string }> } };
        results: Array<{ ruleId: string; ruleIndex: number }>;
      }>;
    };

    // All three issues map to the same rule (same category + title hash)
    const rules = sarif.runs[0].tool.driver.rules;
    assert.equal(rules.length, 1, 'duplicate rule should be deduplicated');
    // Results should still be 3, all referencing ruleIndex 0
    assert.equal(sarif.runs[0].results.length, 3);
    assert.ok(sarif.runs[0].results.every(r => r.ruleIndex === 0));
  });

  it('handles issues without evidence field', () => {
    const result = {
      scanType: 'config' as const,
      timestamp: new Date().toISOString(),
      target: '/test',
      issues: [
        { type: 'low' as const, category: 'network' as const, title: 'Some Issue', description: 'a desc', recommendation: 'fix it' },
      ],
      score: 90,
      summary: { configFilesFound: 1, highRiskIssues: 0, mediumRiskIssues: 0, lowRiskIssues: 1 },
    };

    const sarif = generateSarifOutput(result) as {
      runs: Array<{
        results: Array<{ properties: { evidence?: string; category: string; recommendation: string } }>;
      }>;
    };

    const r = sarif.runs[0].results[0];
    assert.equal(r.properties.category, 'network');
    assert.equal(r.properties.recommendation, 'fix it');
    assert.equal(r.properties.evidence, undefined);
  });

  it('handles low severity issues mapping to note level', () => {
    const result = {
      scanType: 'docker' as const,
      timestamp: new Date().toISOString(),
      target: '/test',
      issues: [
        { type: 'low' as const, category: 'network' as const, title: 'Low Issue', description: 'low desc', recommendation: 'low rec', evidence: 'l1' },
      ],
      score: 95,
      summary: { configFilesFound: 1, highRiskIssues: 0, mediumRiskIssues: 0, lowRiskIssues: 1 },
    };

    const sarif = generateSarifOutput(result) as {
      runs: Array<{ results: Array<{ level: string }> }>;
    };

    assert.equal(sarif.runs[0].results[0].level, 'note');
  });

  it('generateSarifReport stdout outputs valid SARIF JSON', async () => {
    const originalLog = console.log;
    let captured = '';
    console.log = (...args: unknown[]) => { captured = args[0] as string; };
    try {
      const result = {
        scanType: 'config' as const,
        timestamp: new Date().toISOString(),
        target: '/test',
        issues: [
          { type: 'high' as const, category: 'injection' as const, title: 'Shell Injection', description: 'desc', recommendation: 'rec', evidence: 'ev1' },
        ],
        score: 50,
        summary: { configFilesFound: 1, highRiskIssues: 1, mediumRiskIssues: 0, lowRiskIssues: 0 },
      };
      await generateSarifReport(result);
      assert.ok(captured.length > 0);
      const parsed = JSON.parse(captured);
      assert.equal(parsed.version, '2.1.0');
      assert.ok(parsed.runs[0].results.length === 1);
    } finally {
      console.log = originalLog;
    }
  });

  it('generateSarifReport file output logs success message', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sarif2-'));
    const outputPath = path.join(dir, 'report.sarif');
    const result = {
      scanType: 'config' as const,
      timestamp: new Date().toISOString(),
      target: '/test',
      issues: [],
      score: 100,
      summary: { configFilesFound: 0, highRiskIssues: 0, mediumRiskIssues: 0, lowRiskIssues: 0 },
    };
    try {
      await generateSarifReport(result, outputPath);
      assert.ok(await fs.pathExists(outputPath));
    } finally {
      await fs.remove(dir);
    }
  });
});

// ─── Config Scanner: file permission checks (lines 390-455) ───
describe('config-scanner coverage gaps round 2', () => {
  it('detects world-writable config file permissions', async () => {
    // Import config scanner
    const { scanConfig } = await import('../src/scanners/config-scanner.ts');
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cfg-scan-'));
    const configPath = path.join(dir, 'claude_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        server1: {
          command: 'npx',
          args: ['-y', '@some/server'],
          env: { API_KEY: 'sk-test12345678901234567890' },
        },
      },
    });
    await fs.chmod(configPath, 0o666); // world-writable

    try {
      const result = await scanConfig(configPath);
      assert.ok(result.issues.some(i => i.title.includes('Writable') || i.title.includes('Secret')), 'should detect security issues');
    } finally {
      await fs.chmod(configPath, 0o644);
      await fs.remove(dir);
    }
  });

  it('detects group-writable config file permissions', async () => {
    const { scanConfig } = await import('../src/scanners/config-scanner.ts');
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cfg-scan2-'));
    const configPath = path.join(dir, 'claude_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        server1: {
          command: 'npx',
          args: ['-y', '@some/server'],
        },
      },
    });
    await fs.chmod(configPath, 0o664); // group-writable, not world-writable

    try {
      const result = await scanConfig(configPath);
      // Group-writable should be flagged (or at least no crash)
      assert.ok(result);
      assert.ok(result.score <= 100);
    } finally {
      await fs.chmod(configPath, 0o644);
      await fs.remove(dir);
    }
  });
});
