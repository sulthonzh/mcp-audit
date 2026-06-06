#!/usr/bin/env node

import { program } from 'commander';
import { scanConfig } from './scanners/config-scanner';
import { checkServer } from './scanners/server-scanner';
import { generateReport } from './reporter/report-generator';
import { logger } from './utils/logger';
import { loadConfig, initializeConfig } from './config/config-loader';

program
  .name('mcp-audit')
  .description('Security scanner for MCP (Model Context Protocol) servers')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan local MCP configuration files for security issues')
  .option('-v, --verbose', 'Verbose output')
  .option('-o, --output <file>', 'Output file for report')
  .action(async (options) => {
    try {
      logger.info('Starting MCP configuration scan...');
      const config = loadConfig();
      const results = await scanConfig(config, options.verbose);
      await generateReport(results, options.output);
      logger.info('✅ Configuration scan completed');
    } catch (error) {
      logger.error('❌ Configuration scan failed:', error);
      process.exit(1);
    }
  });

program
  .command('check')
  .description('Check a specific MCP server for security issues')
  .argument('<repository>', 'GitHub repository URL or path')
  .option('-v, --verbose', 'Verbose output')
  .option('-o, --output <file>', 'Output file for report')
  .option('--ci', 'CI mode (silent, exit codes only)')
  .option('--depth <number>', 'Scan depth for analysis', '2')
  .action(async (repository, options) => {
    try {
      logger.info(`Starting MCP server analysis for: ${repository}`);
      const config = loadConfig();
      const results = await checkServer(repository, {
        ...config,
        scanDepth: parseInt(options.depth)
      }, options.verbose);
      await generateReport(results, options.output);
      
      if (!options.ci) {
        logger.info('✅ Server analysis completed');
      }
      
      process.exit(results.issues.length > 0 ? 1 : 0);
    } catch (error) {
      logger.error('❌ Server analysis failed:', error);
      process.exit(1);
    }
  });

program
  .command('config')
  .description('Manage MCP Audit configuration')
  .option('--init', 'Initialize configuration file')
  .option('--show', 'Show current configuration')
  .action(async (options) => {
    const config = loadConfig();
    
    if (options.init) {
      await initializeConfig();
      logger.info('✅ Configuration initialized');
      return;
    }
    
    if (options.show) {
      console.log(JSON.stringify(config, null, 2));
      return;
    }
    
    console.log('Use --init to create configuration or --show to view current config');
  });

program.parse();