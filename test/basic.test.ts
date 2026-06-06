import { scanConfig } from '../src/scanners/config-scanner';
import { SecurityResult } from '../src/types/security-result';
import { loadConfig } from '../src/config/config-loader';

describe('MCP Audit Basic Tests', () => {
  test('should scan configuration successfully', async () => {
    const config = loadConfig();
    const result: SecurityResult = await scanConfig(config, false);
    
    expect(result.scanType).toBe('config');
    expect(result.target).toBe('local configuration');
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.summary).toBeDefined();
    expect(Array.isArray(result.issues)).toBe(true);
    
    console.log('✅ Configuration scan test passed');
  });
  
  test('should have proper structure', async () => {
    const config = loadConfig();
    const result: SecurityResult = await scanConfig(config, false);
    
    // Check that all required properties exist
    expect(result).toHaveProperty('timestamp');
    expect(result).toHaveProperty('issues');
    expect(result).toHaveProperty('score');
    expect(result).toHaveProperty('summary');
    expect(result).toHaveProperty('scanType');
    expect(result).toHaveProperty('target');
    
    // Check summary structure
    expect(result.summary).toHaveProperty('configFilesFound');
    expect(result.summary).toHaveProperty('highRiskIssues');
    expect(result.summary).toHaveProperty('mediumRiskIssues');
    expect(result.summary).toHaveProperty('lowRiskIssues');
    
    console.log('✅ Structure test passed');
  });
});