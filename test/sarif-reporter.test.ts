/**
 * Tests for SARIF reporter
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateSarifOutput } from '../src/reporters/sarif-reporter';
import { SecurityResult } from '../src/types/security-result';

const mockResult: SecurityResult = {
  scanType: 'config',
  timestamp: '2026-06-10T20:00:00.000Z',
  target: '/home/user/project/.claude/claude_desktop_config.json',
  issues: [
    {
      type: 'high',
      category: 'injection',
      title: 'Command injection via eval',
      description: 'Server config allows eval() execution which can lead to command injection',
      recommendation: 'Remove eval usage and use safe alternatives',
      evidence: 'eval(userInput)',
    },
    {
      type: 'medium',
      category: 'config',
      title: 'Plaintext secret found',
      description: 'API key stored in plaintext configuration',
      recommendation: 'Use environment variables or secret managers',
      evidence: 'sk-abc123...',
    },
    {
      type: 'low',
      category: 'network',
      title: 'Insecure HTTP endpoint',
      description: 'Server configured with HTTP instead of HTTPS',
      recommendation: 'Use HTTPS for all remote connections',
    },
  ],
  score: 45,
  summary: {
    configFilesFound: 1,
    highRiskIssues: 1,
    mediumRiskIssues: 1,
    lowRiskIssues: 1,
  },
};

describe('SARIF Reporter', () => {
  it('produces valid SARIF v2.1.0 structure', () => {
    const sarif = generateSarifOutput(mockResult) as any;

    assert.equal(sarif.version, '2.1.0');
    assert.ok(sarif.$schema);
    assert.ok(Array.isArray(sarif.runs));
    assert.equal(sarif.runs.length, 1);
  });

  it('includes tool driver info', () => {
    const sarif = generateSarifOutput(mockResult) as any;
    const driver = sarif.runs[0].tool.driver;

    assert.equal(driver.name, 'mcp-audit');
    assert.equal(driver.version, '1.2.0');
    assert.ok(driver.informationUri);
  });

  it('maps severity levels correctly', () => {
    const sarif = generateSarifOutput(mockResult) as any;
    const results = sarif.runs[0].results;

    // high → error
    assert.equal(results[0].level, 'error');
    // medium → warning
    assert.equal(results[1].level, 'warning');
    // low → note
    assert.equal(results[2].level, 'note');
  });

  it('creates unique rules for distinct issues', () => {
    const sarif = generateSarifOutput(mockResult) as any;
    const rules = sarif.runs[0].tool.driver.rules;

    assert.equal(rules.length, 3);
    assert.ok(rules.every((r: any) => r.id && r.shortDescription));
  });

  it('includes properties with recommendations', () => {
    const sarif = generateSarifOutput(mockResult) as any;
    const results = sarif.runs[0].results;

    assert.equal(results[0].properties.recommendation, 'Remove eval usage and use safe alternatives');
    assert.equal(results[0].properties.evidence, 'eval(userInput)');
    assert.equal(results[0].properties.category, 'injection');
  });

  it('handles empty issues list', () => {
    const clean: SecurityResult = {
      ...mockResult,
      issues: [],
      score: 100,
      summary: { ...mockResult.summary, highRiskIssues: 0, mediumRiskIssues: 0, lowRiskIssues: 0 },
    };

    const sarif = generateSarifOutput(clean) as any;

    assert.equal(sarif.runs[0].results.length, 0);
    assert.equal(sarif.runs[0].tool.driver.rules.length, 0);
    assert.equal(sarif.runs[0].properties.securityScore, 100);
  });

  it('includes scan metadata in run properties', () => {
    const sarif = generateSarifOutput(mockResult) as any;
    const props = sarif.runs[0].properties;

    assert.equal(props.scanType, 'config');
    assert.equal(props.securityScore, 45);
    assert.equal(props.summary.highRiskIssues, 1);
  });

  it('uses file:// URI for absolute paths', () => {
    const sarif = generateSarifOutput(mockResult) as any;
    const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;

    assert.ok(uri.startsWith('file://'));
  });

  it('handles relative path targets without file:// prefix', () => {
    const relResult: SecurityResult = {
      ...mockResult,
      target: './config/mcp.json',
    };

    const sarif = generateSarifOutput(relResult) as any;
    const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;

    assert.equal(uri, './config/mcp.json');
  });
});
