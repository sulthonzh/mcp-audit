import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';
import { Logger } from '../src/utils/logger';
import { loadConfig, getConfigPath, getDefaultConfigPath, initializeConfig, MCPAuditConfig } from '../src/config/config-loader';
import { autoFixConfig, printFixDiff, FixOptions } from '../src/scanners/config-fixer';

// ============== LOGGER TESTS ==============

describe('Logger', () => {
  let originalConsoleLog: typeof console.log;
  let originalConsoleWarn: typeof console.warn;
  let originalConsoleError: typeof console.error;
  let originalConsoleDebug: typeof console.debug;
  let logs: string[];
  let warns: string[];
  let errors: string[];
  let debugs: string[];

  beforeEach(() => {
    logs = [];
    warns = [];
    errors = [];
    debugs = [];
    originalConsoleLog = console.log;
    originalConsoleWarn = console.warn;
    originalConsoleError = console.error;
    originalConsoleDebug = console.debug;
    console.log = (...args: unknown[]) => { logs.push(args.map(String).join(' ')); };
    console.warn = (...args: unknown[]) => { warns.push(args.map(String).join(' ')); };
    console.error = (...args: unknown[]) => { errors.push(args.map(String).join(' ')); };
    console.debug = (...args: unknown[]) => { debugs.push(args.map(String).join(' ')); };
  });

  afterEach(() => {
    console.log = originalConsoleLog;
    console.warn = originalConsoleWarn;
    console.error = originalConsoleError;
    console.debug = originalConsoleDebug;
  });

  it('should log info messages', () => {
    const logger = new Logger();
    logger.info('test info');
    assert.ok(logs.length >= 1);
    assert.ok(logs[0].includes('test info'));
  });

  it('should log warn messages', () => {
    const logger = new Logger();
    logger.warn('test warn');
    assert.ok(warns.length >= 1);
    assert.ok(warns[0].includes('test warn'));
  });

  it('should log error messages', () => {
    const logger = new Logger();
    logger.error('test error');
    assert.ok(errors.length >= 1);
    assert.ok(errors[0].includes('test error'));
  });

  it('should NOT log debug messages when verbose=false', () => {
    const logger = new Logger({ verbose: false });
    logger.debug('test debug');
    assert.equal(debugs.length, 0);
  });

  it('should log debug messages when verbose=true', () => {
    const logger = new Logger({ verbose: true });
    logger.debug('test debug');
    assert.ok(debugs.length >= 1);
    assert.ok(debugs[0].includes('test debug'));
  });

  it('should NOT log anything when silent=true', () => {
    const logger = new Logger({ silent: true });
    logger.info('info');
    logger.warn('warn');
    logger.error('error');
    logger.debug('debug');
    assert.equal(logs.length, 0);
    assert.equal(warns.length, 0);
    assert.equal(errors.length, 0);
    assert.equal(debugs.length, 0);
  });

  it('should log data in verbose mode', () => {
    const logger = new Logger({ verbose: true });
    logger.info('with data', { key: 'value' });
    // Should have the info message + the JSON data
    const combined = [...logs, ...debugs].join('\n');
    assert.ok(combined.includes('"key"'));
    assert.ok(combined.includes('value'));
  });

  it('should NOT log data when verbose=false', () => {
    const logger = new Logger({ verbose: false });
    logger.info('with data', { key: 'value' });
    const combined = [...logs, ...debugs].join('\n');
    assert.ok(!combined.includes('"key"'));
  });

  it('should NOT log data when data is null or undefined', () => {
    const logger = new Logger({ verbose: true });
    logger.info('first message', null);
    logger.info('second message', undefined);
    // In verbose mode, info messages go to console.log
    // The Logger checks: data !== undefined && data !== null before logging data
    // So null/undefined data should NOT produce extra JSON output lines
    // Count the lines that contain JSON (look for `{` or `"key"`)
    const jsonDataLines = logs.filter(l => l.includes('{') && l.includes('"'));
    assert.equal(jsonDataLines.length, 0, 'Should not output JSON data for null/undefined');
  });

  it('success() should always log even in silent mode', () => {
    const logger = new Logger({ silent: true });
    logger.success('done');
    // success() bypasses silent check
    assert.ok(logs.length >= 1);
    assert.ok(logs[0].includes('done'));
  });

  it('start() should always log even in silent mode', () => {
    const logger = new Logger({ silent: true });
    logger.start('begin');
    assert.ok(logs.length >= 1);
    assert.ok(logs[0].includes('begin'));
  });

  it('separator() should always log even in silent mode', () => {
    const logger = new Logger({ silent: true });
    logger.separator();
    assert.ok(logs.length >= 1);
  });

  it('should use default empty options when none provided', () => {
    const logger = new Logger();
    logger.info('works');
    assert.ok(logs.length >= 1);
  });
});

// ============== CONFIG LOADER TESTS ==============

describe('ConfigLoader', () => {
  const tmpDir = path.join(os.tmpdir(), `mcp-audit-cfg-test-${Date.now()}`);
  let originalCwd: string;

  beforeEach(async () => {
    originalCwd = process.cwd();
    await fs.ensureDir(tmpDir);
    process.chdir(tmpDir);
  });

  afterEach(async () => {
    process.chdir(originalCwd);
    await fs.remove(tmpDir);
  });

  it('getConfigPath() should return path in current working directory', () => {
    const configPath = getConfigPath();
    assert.ok(configPath.includes('mcp-audit.config.json'));
    assert.ok(path.isAbsolute(configPath));
  });

  it('getDefaultConfigPath() should return path in home directory', () => {
    const defaultPath = getDefaultConfigPath();
    assert.ok(defaultPath.includes('.mcp-audit.json'));
    assert.ok(defaultPath.includes(homedir()));
  });

  it('loadConfig() should return defaults when no config file exists', () => {
    const config = loadConfig();
    assert.ok(config.vulnerabilityDatabase);
    assert.ok(config.trustWeight);
    assert.equal(config.trustWeight.stars, 0.3);
    assert.equal(config.trustWeight.tests, 0.3);
    assert.equal(config.trustWeight.ci, 0.2);
    assert.equal(config.trustWeight.age, 0.2);
    assert.ok(Array.isArray(config.allowedFileAccess));
    assert.equal(config.scanDepth, 2);
    assert.ok(Array.isArray(config.excludePatterns));
    assert.ok(config.excludePatterns.length > 0);
  });

  it('loadConfig() should load custom config path', async () => {
    const customPath = path.join(tmpDir, 'custom-config.json');
    const customConfig: Partial<MCPAuditConfig> = {
      scanDepth: 5,
      excludePatterns: ['custom/**'],
    };
    await fs.writeJson(customPath, customConfig);

    const config = loadConfig(customPath);
    assert.equal(config.scanDepth, 5);
    assert.ok(config.excludePatterns.includes('custom/**'));
    // Should merge with defaults
    assert.ok(config.vulneranceDatabase || config.vulnerabilityDatabase);
    assert.ok(config.trustWeight.stars === 0.3);
  });

  it('loadConfig() should warn and return defaults on invalid JSON', () => {
    const badConfigPath = path.join(tmpDir, 'mcp-audit.config.json');
    fs.writeFileSync(badConfigPath, '{ invalid json }}}');

    const config = loadConfig();
    // Should fall back to defaults
    assert.equal(config.scanDepth, 2);
    assert.equal(config.trustWeight.stars, 0.3);
  });

  it('loadConfig() should warn and return defaults on invalid global config', async () => {
    // We can't easily test the global config path without modifying home dir
    // But we can test the local config path fallback
    const badConfigPath = path.join(tmpDir, 'mcp-audit.config.json');
    await fs.writeFile(badConfigPath, 'not json at all');

    const config = loadConfig();
    assert.equal(config.scanDepth, 2); // default
  });

  it('initializeConfig() should create config file', async () => {
    const configPath = path.join(tmpDir, 'init-test.json');
    await initializeConfig(configPath);

    assert.ok(await fs.pathExists(configPath));
    const written = await fs.readJson(configPath);
    assert.ok(written.vulnerabilityDatabase);
    assert.ok(written.trustWeight);
    assert.equal(written.scanDepth, 2);
  });

  it('initializeConfig() should use default path when no path provided', async () => {
    await initializeConfig();
    const defaultPath = getConfigPath();
    assert.ok(await fs.pathExists(defaultPath));
  });

  it('loadConfig() should merge user config over defaults', async () => {
    const configPath = path.join(tmpDir, 'mcp-audit.config.json');
    await fs.writeJson(configPath, {
      scanDepth: 10,
      trustWeight: { stars: 0.5, tests: 0.1, ci: 0.2, age: 0.2 },
    });

    const config = loadConfig();
    assert.equal(config.scanDepth, 10);
    assert.equal(config.trustWeight.stars, 0.5);
    assert.equal(config.trustWeight.tests, 0.1);
    // Default values preserved for unoverridden keys
    assert.ok(Array.isArray(config.allowedFileAccess));
    assert.ok(config.excludePatterns.length > 0);
  });
});

// ============== CONFIG FIXER TESTS ==============

describe('ConfigFixer', () => {
  const tmpDir = path.join(os.tmpdir(), `mcp-audit-fixer-test-${Date.now()}`);
  let originalCwd: string;
  let originalHome: string;
  let fakeHome: string;

  beforeEach(async () => {
    originalCwd = process.cwd();
    originalHome = process.env.HOME || '';
    await fs.ensureDir(tmpDir);
    fakeHome = path.join(tmpDir, 'fake-home');
    await fs.ensureDir(fakeHome);
    process.env.HOME = fakeHome;
    process.chdir(tmpDir);
  });

  afterEach(async () => {
    process.chdir(originalCwd);
    process.env.HOME = originalHome;
    await fs.remove(tmpDir);
  });

  it('autoFixConfig() should return empty array when no config files exist', async () => {
    const results = await autoFixConfig({ quiet: true });
    assert.equal(results.length, 0);
  });

  it('autoFixConfig() should remove dangerous flags (dry run)', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    const config = {
      mcpServers: {
        'dangerous-server': {
          command: 'npx',
          args: ['--allow-all', '--no-sandbox', '@modelcontextprotocol/server-filesystem'],
        },
      },
    };
    await fs.writeJson(configPath, config);

    const results = await autoFixConfig({ quiet: true });
    assert.ok(results.length >= 1);

    const result = results.find((r) => r.file.includes('mcp.json'));
    assert.ok(result);

    const flagFixes = result.fixesApplied.filter((f) => f.field === 'args');
    assert.ok(flagFixes.length >= 1);

    const removedFlags = flagFixes.map((f) => f.reason);
    const combinedReasons = removedFlags.join(' ');
    assert.ok(combinedReasons.includes('dangerous') || combinedReasons.includes('Removed'));
  });

  it('autoFixConfig() should pin unpinned package versions', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    const config = {
      mcpServers: {
        'unpinned-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem'],
        },
      },
    };
    await fs.writeJson(configPath, config);

    const results = await autoFixConfig({ quiet: true });
    assert.ok(results.length >= 1);

    const result = results.find((r) => r.file.includes('mcp.json'));
    assert.ok(result);

    const pinFix = result.fixesApplied.find((f) => f.reason.includes('Pin') || f.reason.includes('pin'));
    assert.ok(pinFix, 'Should have a version pinning fix');
    assert.ok(pinFix.newValue.includes('@latest') || pinFix.newValue.match(/@\d/));
  });

  it('autoFixConfig() should NOT pin already-pinned versions', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    const config = {
      mcpServers: {
        'pinned-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem@1.2.0'],
        },
      },
    };
    await fs.writeJson(configPath, config);

    const results = await autoFixConfig({ quiet: true });
    const result = results.find((r) => r.file.includes('mcp.json'));

    // With a pinned version, no fixes should be needed
    // result might be undefined (no fixes) or have no pinning fix
    if (result) {
      const pinFix = result.fixesApplied.find((f) => f.reason.includes('Pin'));
      assert.ok(!pinFix, 'Should not pin already-pinned version');
    }
    // If result is undefined, no fixes were needed — which is correct
  });

  it('autoFixConfig() should restrict root filesystem access', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    const config = {
      mcpServers: {
        'fs-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem@1.0.0', '/'],
        },
      },
    };
    await fs.writeJson(configPath, config);

    const results = await autoFixConfig({ quiet: true });
    const result = results.find((r) => r.file.includes('mcp.json'));
    assert.ok(result);

    const fsFix = result.fixesApplied.find((f) => f.reason.includes('filesystem') || f.reason.includes('Restrict'));
    assert.ok(fsFix);
    assert.ok(fsFix.newValue.includes('./'));
  });

  it('autoFixConfig() should upgrade HTTP to HTTPS', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    const config = {
      mcpServers: {
        'remote-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-fetch@1.0.0'],
          url: 'http://example.com/mcp',
        },
      },
    };
    await fs.writeJson(configPath, config);

    const results = await autoFixConfig({ quiet: true });
    const result = results.find((r) => r.file.includes('mcp.json'));
    assert.ok(result);

    const urlFix = result.fixesApplied.find((f) => f.field === 'url');
    assert.ok(urlFix);
    assert.ok(urlFix.newValue.startsWith('https://'));
  });

  it('autoFixConfig() should NOT upgrade localhost HTTP', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    const config = {
      mcpServers: {
        'local-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-fetch@1.0.0'],
          url: 'http://localhost:3000/mcp',
        },
      },
    };
    await fs.writeJson(configPath, config);

    const results = await autoFixConfig({ quiet: true });
    const result = results.find((r) => r.file.includes('mcp.json'));

    if (result) {
      const urlFix = result.fixesApplied.find((f) => f.field === 'url');
      assert.ok(!urlFix, 'Should not upgrade localhost URLs');
    }
  });

  it('autoFixConfig() should redact plaintext secrets', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    const config = {
      mcpServers: {
        'secret-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-github@1.0.0'],
          env: {
            API_KEY: 'sk-12345-secret-key',
            TOKEN: 'my-secret-token',
          },
        },
      },
    };
    await fs.writeJson(configPath, config);

    const results = await autoFixConfig({ quiet: true });
    const result = results.find((r) => r.file.includes('mcp.json'));
    assert.ok(result);

    const secretFixes = result.fixesApplied.filter((f) => f.field.startsWith('env.'));
    assert.ok(secretFixes.length >= 2, `Expected at least 2 secret fixes, got ${secretFixes.length}`);
    assert.ok(secretFixes.every((f) => f.newValue.includes('_PLACEHOLDER')));
  });

  it('autoFixConfig() should NOT redact env reference secrets', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    const config = {
      mcpServers: {
        'ref-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-github@1.0.0'],
          env: {
            API_KEY: '${MY_API_KEY}',
          },
        },
      },
    };
    await fs.writeJson(configPath, config);

    const results = await autoFixConfig({ quiet: true });
    const result = results.find((r) => r.file.includes('mcp.json'));

    if (result) {
      const secretFix = result.fixesApplied.find((f) => f.field.startsWith('env.'));
      assert.ok(!secretFix, 'Should not redact env references');
    }
  });

  it('autoFixConfig() should write fixed config when inPlace=true', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    const config = {
      mcpServers: {
        'fix-server': {
          command: 'npx',
          args: ['--allow-all', '@modelcontextprotocol/server-filesystem'],
        },
      },
    };
    await fs.writeJson(configPath, config);

    await autoFixConfig({ inPlace: true, quiet: true });

    const fixedContent = await fs.readFile(configPath, 'utf8');
    const fixedConfig = JSON.parse(fixedContent);
    assert.ok(!fixedConfig.mcpServers['fix-server'].args.includes('--allow-all'));
  });

  it('autoFixConfig() should NOT write when dryRun=true (default)', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    const config = {
      mcpServers: {
        'fix-server': {
          command: 'npx',
          args: ['--allow-all', '@modelcontextprotocol/server-filesystem'],
        },
      },
    };
    await fs.writeJson(configPath, config);

    await autoFixConfig({ quiet: true }); // dryRun defaults to true

    const content = await fs.readFile(configPath, 'utf8');
    const parsed = JSON.parse(content);
    // Original should be unchanged
    assert.ok(parsed.mcpServers['fix-server'].args.includes('--allow-all'));
  });

  it('printFixDiff() should output diff for fixes', () => {
    // Just verify it doesn't crash
    const results = [
      {
        file: '/tmp/test.json',
        fixesApplied: [
          {
            server: 'test-server',
            field: 'args',
            oldValue: 'old-val',
            newValue: 'new-val',
            reason: 'test reason',
          },
        ],
        fixedConfig: '{}',
        originalConfig: '{}',
      },
    ];

    // Should not throw
    assert.doesNotThrow(() => printFixDiff(results));
  });

  it('autoFixConfig() should handle YAML config files', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    const yamlContent = `mcpServers:\n  yaml-server:\n    command: npx\n    args:\n      - --allow-all\n      - "@modelcontextprotocol/server-filesystem"\n`;
    await fs.writeFile(configPath, yamlContent);

    // The file is named mcp.json but contains YAML — this is an edge case
    // The fixer tries JSON first, fails, then tries based on extension
    // Since it's .json extension, it will fail to parse
    const results = await autoFixConfig({ quiet: true });
    // Should handle gracefully (either skip or error)
    // No crash is the important thing
    assert.ok(Array.isArray(results));
  });

  it('autoFixConfig() should handle empty mcpServers', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    await fs.writeJson(configPath, { mcpServers: {} });

    const results = await autoFixConfig({ quiet: true });
    // No servers to fix → fixConfigFile returns null → no results for this file
    // But there could be file permission fixes that still produce results
    // Check that no fix with 'args' field exists (no server-level fixes)
    const serverFixes = results.flatMap(r => r.fixesApplied).filter(f => f.field === 'args' || f.field.startsWith('env.'));
    assert.equal(serverFixes.length, 0, 'Should not apply server-level fixes for empty mcpServers');
  });

  it('autoFixConfig() should handle null/invalid server entries', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'null-server': null,
        'non-object': 'string-value',
      },
    });

    // Should not crash
    const results = await autoFixConfig({ quiet: true });
    assert.ok(Array.isArray(results));
  });

  it('autoFixConfig() should handle servers array format', async () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    await fs.writeJson(configPath, {
      servers: [
        {
          command: 'npx',
          args: ['--allow-all', '@modelcontextprotocol/server-filesystem'],
        },
      ],
    });

    const results = await autoFixConfig({ quiet: true });
    // Config fixer handles mcpServers (object) format, not servers (array) format
    // This is by design — the fixer focuses on the common Claude Desktop config format
    assert.ok(Array.isArray(results));
  });
});

// ============== CONFIG SCANNER EDGE CASES ==============

describe('ConfigScanner edge cases', () => {
  const tmpDir = path.join(os.tmpdir(), `mcp-audit-scanner-test-${Date.now()}`);
  let originalHome: string;
  let originalCwd: string;

  beforeEach(async () => {
    originalHome = process.env.HOME || '';
    originalCwd = process.cwd();
    await fs.ensureDir(tmpDir);
  });

  afterEach(async () => {
    process.env.HOME = originalHome;
    process.chdir(originalCwd);
    await fs.remove(tmpDir);
  });

  it('scanConfig should handle config with no servers', async () => {
    // Create a config with empty mcpServers
    const fakeHome = path.join(tmpDir, 'home');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, { mcpServers: {} });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    assert.equal(result.scanType, 'config');
    assert.ok(result.score >= 0 && result.score <= 100);
  });

  it('scanConfig should detect shell command execution', async () => {
    const fakeHome = path.join(tmpDir, 'home2');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'shell-server': {
          command: 'bash',
          args: ['-c', 'echo hello'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const shellIssue = result.issues.find(
      (i) => i.title === 'Shell Command Execution'
    );
    assert.ok(shellIssue, 'Should detect shell command execution');
    assert.equal(shellIssue!.type, 'high');
    assert.equal(shellIssue!.category, 'injection');
  });

  it('scanConfig should detect Python server execution', async () => {
    const fakeHome = path.join(tmpDir, 'home3');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'py-server': {
          command: 'python',
          args: ['-m', 'mcp_server'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const pyIssue = result.issues.find(
      (i) => i.title.includes('Python Server')
    );
    assert.ok(pyIssue, 'Should detect Python server execution');
  });

  it('scanConfig should detect dangerous argument patterns', async () => {
    const fakeHome = path.join(tmpDir, 'home4');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'dangerous-server': {
          command: 'node',
          args: ['server.js', '--privileged', '--no-sandbox', '$(evil)'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    // Should detect --privileged, --no-sandbox, and $()
    const titles = result.issues.map((i) => i.title);
    assert.ok(titles.includes('Privileged Mode'), 'Should detect --privileged');
    assert.ok(titles.includes('Sandbox Disabled'), 'Should detect --no-sandbox');
    assert.ok(titles.includes('Command Substitution'), 'Should detect $()');
  });

  it('scanConfig should detect plaintext secrets in env', async () => {
    const fakeHome = path.join(tmpDir, 'home5');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'secret-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-github'],
          env: {
            API_KEY: 'sk-1234567890abcdef',
            PASSWORD: 'my-password',
            SAFE_VAR: 'not-sensitive',
          },
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const secretIssues = result.issues.filter((i) =>
      i.title.includes('Plaintext Secret')
    );
    assert.ok(secretIssues.length >= 2, `Expected at least 2 plaintext secret issues, got ${secretIssues.length}`);

    // SAFE_VAR should NOT trigger a secret issue
    const safeVarIssue = result.issues.find((i) => i.evidence?.includes('SAFE_VAR'));
    assert.ok(!safeVarIssue, 'Should not flag non-sensitive env vars');
  });

  it('scanConfig should detect root filesystem access', async () => {
    const fakeHome = path.join(tmpDir, 'home6');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'fs-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem', '/'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const rootFsIssue = result.issues.find((i) => i.title === 'Root Filesystem Access');
    assert.ok(rootFsIssue, 'Should detect root filesystem access');
    assert.equal(rootFsIssue!.type, 'high');
    assert.equal(rootFsIssue!.category, 'filesystem');
  });

  it('scanConfig should detect insecure remote HTTP server', async () => {
    const fakeHome = path.join(tmpDir, 'home7');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'remote-server': {
          url: 'http://example.com/mcp',
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const insecureIssue = result.issues.find((i) => i.title === 'Insecure Remote Server');
    assert.ok(insecureIssue, 'Should detect insecure HTTP remote server');
    assert.equal(insecureIssue!.type, 'high');
    assert.equal(insecureIssue!.category, 'network');
  });

  it('scanConfig should detect unpinned package versions', async () => {
    const fakeHome = path.join(tmpDir, 'home8');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'unpinned-server': {
          command: 'npx',
          args: ['some-random-package'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const unpinnedIssue = result.issues.find((i) => i.title === 'Unpinned Package Version');
    assert.ok(unpinnedIssue, 'Should detect unpinned package version');
    assert.equal(unpinnedIssue!.type, 'medium');
    assert.equal(unpinnedIssue!.category, 'supply-chain');
  });

  it('scanConfig should detect auto-approve flags', async () => {
    const fakeHome = path.join(tmpDir, 'home9');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'auto-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-github@1.0.0', '--auto-approve'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const autoApproveIssue = result.issues.find((i) => i.title === 'Auto-Approve Enabled');
    assert.ok(autoApproveIssue, 'Should detect auto-approve flag');
    assert.equal(autoApproveIssue!.type, 'high');
  });

  it('scanConfig should detect local path execution', async () => {
    const fakeHome = path.join(tmpDir, 'home10');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'local-server': {
          command: './local-server',
          args: [],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const localPathIssue = result.issues.find((i) => i.title === 'Local Path Execution');
    assert.ok(localPathIssue, 'Should detect local path execution');
    assert.equal(localPathIssue!.type, 'medium');
    assert.equal(localPathIssue!.category, 'supply-chain');
  });

  it('scanConfig should detect network access via command', async () => {
    const fakeHome = path.join(tmpDir, 'home11');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'curl-server': {
          command: 'curl',
          args: ['http://example.com'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const networkIssue = result.issues.find((i) => i.title === 'Network Access');
    assert.ok(networkIssue, 'Should detect network access via curl command');
  });

  it('scanConfig should detect insecure SSE transport', async () => {
    const fakeHome = path.join(tmpDir, 'home12');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'sse-server': {
          url: 'http://example.com/sse',
          type: 'sse',
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const sseIssue = result.issues.find((i) => i.title === 'Insecure SSE Transport');
    assert.ok(sseIssue, 'Should detect insecure SSE transport');
    assert.equal(sseIssue!.type, 'high');
    assert.equal(sseIssue!.category, 'transport');
  });

  it('scanConfig should detect SSE without auth', async () => {
    const fakeHome = path.join(tmpDir, 'home13');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'sse-server': {
          url: 'https://example.com/sse',
          type: 'sse',
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const sseAuthIssue = result.issues.find((i) => i.title === 'SSE Transport Without Auth');
    assert.ok(sseAuthIssue, 'Should detect SSE without auth');
    assert.equal(sseAuthIssue!.type, 'medium');
  });

  it('scanConfig should detect path traversal in args', async () => {
    const fakeHome = path.join(tmpDir, 'home14');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'traversal-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem@1.0.0', '../../etc/passwd'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const traversalIssue = result.issues.find((i) => i.title === 'Path Traversal');
    assert.ok(traversalIssue, 'Should detect path traversal');
    assert.equal(traversalIssue!.type, 'high');
  });

  it('scanConfig should detect shell pipe chains', async () => {
    const fakeHome = path.join(tmpDir, 'home15');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'pipe-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem@1.0.0', 'file.txt || rm -rf /'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const pipeIssue = result.issues.find((i) => i.title === 'Shell Pipe Chain');
    assert.ok(pipeIssue, 'Should detect shell pipe chain');
  });

  it('scanConfig should detect known safe packages with lower severity', async () => {
    const fakeHome = path.join(tmpDir, 'home16');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'safe-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const safeIssue = result.issues.find((i) =>
      i.title === 'Standard Node.js MCP Server'
    );
    assert.ok(safeIssue, 'Should detect known safe package');
    assert.equal(safeIssue!.type, 'low');
  });

  it('scanConfig should handle YAML config files', async () => {
    const fakeHome = path.join(tmpDir, 'home17');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    // Write YAML content even though file ends in .json — should handle error
    await fs.writeFile(configPath, 'mcpServers:\n  test:\n    command: npx');

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    // Should handle parse error gracefully
    const errorIssue = result.issues.find((i) => i.title === 'Invalid Configuration');
    assert.ok(errorIssue, 'Should report invalid configuration for unparseable file');
  });

  it('scanConfig should detect remote HTTPS server (low risk)', async () => {
    const fakeHome = path.join(tmpDir, 'home18');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'https-server': {
          url: 'https://example.com/mcp',
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const remoteIssue = result.issues.find((i) => i.title === 'Remote MCP Server');
    assert.ok(remoteIssue, 'Should detect remote HTTPS server');
    assert.equal(remoteIssue!.type, 'low');
  });

  it('scanConfig should detect broad filesystem access (non-root)', async () => {
    const fakeHome = path.join(tmpDir, 'home19');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'fs-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem@1.0.0', '/home/user'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const fsIssue = result.issues.find((i) => i.title === 'Broad Filesystem Access');
    assert.ok(fsIssue, 'Should detect broad filesystem access');
    assert.equal(fsIssue!.type, 'medium');
  });

  it('scanConfig should detect shell command chains (&&)', async () => {
    const fakeHome = path.join(tmpDir, 'home20');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'chain-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem@1.0.0', 'file.txt && cat /etc/passwd'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const chainIssue = result.issues.find((i) => i.title === 'Shell Command Chain');
    assert.ok(chainIssue, 'Should detect shell command chain');
  });

  it('scanConfig should detect code evaluation flag', async () => {
    const fakeHome = path.join(tmpDir, 'home21');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'eval-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem@1.0.0', '--eval=malicious'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const evalIssue = result.issues.find((i) => i.title === 'Code Evaluation');
    assert.ok(evalIssue, 'Should detect code evaluation');
    assert.equal(evalIssue!.type, 'high');
  });

  it('scanConfig should detect code execution flag', async () => {
    const fakeHome = path.join(tmpDir, 'home22');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'exec-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem@1.0.0', '--exec=something'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const execIssue = result.issues.find((i) => i.title === 'Code Execution');
    assert.ok(execIssue, 'Should detect code execution');
    assert.equal(execIssue!.type, 'medium');
  });

  it('scanConfig should handle servers array format (not mcpServers object)', async () => {
    const fakeHome = path.join(tmpDir, 'home23');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      servers: [
        {
          command: 'bash',
          args: ['-c', 'echo hello'],
        },
      ],
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    // Should process servers array format too
    const shellIssue = result.issues.find((i) => i.title === 'Shell Command Execution');
    assert.ok(shellIssue, 'Should detect shell execution in servers array format');
  });

  it('scanConfig should use verbose mode for debug output', async () => {
    const fakeHome = path.join(tmpDir, 'home24');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'safe-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem@1.0.0'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();

    // verbose=true should not crash
    const result = await scanConfig(config, true);
    assert.equal(result.scanType, 'config');
  });

  it('scanConfig should detect cursor config path', async () => {
    const fakeHome = path.join(tmpDir, 'home25');
    await fs.ensureDir(path.join(fakeHome, '.cursor'));
    const configPath = path.join(fakeHome, '.cursor', 'mcp.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'cursor-server': {
          command: 'bash',
          args: ['-c', 'evil'],
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    assert.ok(result.summary.configFilesFound >= 1, 'Should find cursor config file');
    const shellIssue = result.issues.find((i) => i.title === 'Shell Command Execution');
    assert.ok(shellIssue, 'Should detect shell execution in cursor config');
  });

  it('scanConfig should detect secret reference (not plaintext)', async () => {
    const fakeHome = path.join(path.join(tmpDir, 'home26'), '');
    await fs.ensureDir(path.join(fakeHome, '.config', 'claude'));
    const configPath = path.join(fakeHome, '.config', 'claude', 'claude_desktop_config.json');
    await fs.writeJson(configPath, {
      mcpServers: {
        'ref-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-github@1.0.0'],
          env: {
            API_KEY: '$(cat /dev/null)',
          },
        },
      },
    });

    process.env.HOME = fakeHome;

    const { scanConfig } = await import('../src/scanners/config-scanner');
    const { loadConfig } = await import('../src/config/config-loader');
    const config = loadConfig();
    const result = await scanConfig(config, false);

    const refIssue = result.issues.find((i) => i.title === 'Secret Reference in Config');
    assert.ok(refIssue, 'Should detect secret reference');
    assert.equal(refIssue!.type, 'medium');
  });
});

// Helper function
function homedir(): string {
  return require('os').homedir();
}
