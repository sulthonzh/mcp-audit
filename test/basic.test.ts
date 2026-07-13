import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scanConfig } from '../src/scanners/config-scanner.ts';
import { SecurityResult } from '../src/types/security-result';
import { loadConfig } from '../src/config/config-loader.ts';

describe('MCP Audit Basic Tests', () => {
  it('should scan configuration successfully', async () => {
    const config = loadConfig();
    const result: SecurityResult = await scanConfig(config, false);

    assert.equal(result.scanType, 'config');
    assert.equal(result.target, 'local configuration');
    assert.ok(result.score >= 0);
    assert.ok(result.score <= 100);
    assert.ok(result.summary);
    assert.ok(Array.isArray(result.issues));
  });

  it('should have proper structure', async () => {
    const config = loadConfig();
    const result: SecurityResult = await scanConfig(config, false);

    assert.ok(result.timestamp);
    assert.ok(result.issues);
    assert.ok(typeof result.score === 'number');
    assert.ok(result.summary);
    assert.ok(result.scanType);
    assert.ok(result.target);

    assert.ok(typeof result.summary.configFilesFound === 'number');
    assert.ok(typeof result.summary.highRiskIssues === 'number');
    assert.ok(typeof result.summary.mediumRiskIssues === 'number');
    assert.ok(typeof result.summary.lowRiskIssues === 'number');
  });
});
