// MCP Audit - Main entry point
// This file serves as the main entry point for the package

export { scanConfig } from './scanners/config-scanner';
export { checkServer } from './scanners/server-scanner';
export { generateReport } from './reporter/report-generator';
export { loadConfig, initializeConfig } from './config/config-loader';
export { logger } from './utils/logger';
export { scanDocker } from './scanners/docker-scanner';
export { SecurityResult, SecurityIssue } from './types/security-result';

// Re-export command for programmatic usage
// Note: program is not exported due to circular dependency
// Use cli module directly for programmatic access