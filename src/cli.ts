#!/usr/bin/env node

import { program } from 'commander';
import { scanConfig } from './scanners/config-scanner';
import { checkServer } from './scanners/server-scanner';
import { generateReport } from './reporter/report-generator';
import { logger } from './utils/logger';
import { loadConfig, initializeConfig } from './config/config-loader';
import { scanDocker } from './scanners/docker-scanner';
import { scanK8s } from './scanners/k8s-scanner';
import { scanHelm } from './scanners/helm-scanner';
import { autoFixConfig, printFixDiff } from './scanners/config-fixer';
import chalk from 'chalk';

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
  .command('docker')
  .description('Scan Dockerfiles, compose files, and .env for container security issues')
  .argument('<path>', 'Directory or file to scan')
  .option('-v, --verbose', 'Verbose output')
  .option('-o, --output <file>', 'Output file for report')
  .option('--strict', 'Treat warnings as errors (exit 1)')
  .option('--ci', 'CI mode (no color, exit codes only)')
  .action(async (targetPath, options) => {
    try {
      if (!options.ci) logger.info(`Scanning Docker configs in: ${targetPath}`);
      const results = await scanDocker(targetPath, { strict: options.strict });
      await generateReport(results, options.output);

      if (!options.ci) {
        const score = results.score ?? 'N/A';
        const issueCount = results.issues.length;
        logger.info(`✅ Docker scan completed — ${issueCount} issue(s) found, score: ${score}`);
      }

      const hasHigh = results.issues.some((i: any) => i.severity === 'high');
      const fail = options.strict ? results.issues.length > 0 : hasHigh;
      process.exit(fail ? 1 : 0);
    } catch (error) {
      logger.error('❌ Docker scan failed:', error);
      process.exit(1);
    }
  });

program
  .command('k8s')
  .description('Scan Kubernetes manifests (YAML) for security misconfigurations')
  .argument('<path>', 'Directory or file to scan')
  .option('-v, --verbose', 'Verbose output')
  .option('-o, --output <file>', 'Output file for report')
  .option('--strict', 'Treat all issues as failures (exit 1)')
  .option('--ci', 'CI mode (no color, exit codes only)')
  .action(async (targetPath, options) => {
    try {
      if (!options.ci) logger.info(`Scanning K8s manifests in: ${targetPath}`);
      const results = await scanK8s(targetPath, { strict: options.strict });
      await generateReport(results, options.output);

      if (!options.ci) {
        const score = results.score ?? 'N/A';
        const issueCount = results.issues.length;
        logger.info(`✅ K8s scan completed — ${issueCount} issue(s) found, score: ${score}`);
      }

      const hasHigh = results.issues.some((i: any) => i.type === 'high');
      const fail = options.strict ? results.issues.length > 0 : hasHigh;
      process.exit(fail ? 1 : 0);
    } catch (error) {
      logger.error('❌ K8s scan failed:', error);
      process.exit(1);
    }
  });

program
  .command('helm')
  .description('Scan Helm charts for security misconfigurations')
  .argument('<path>', 'Helm chart directory or parent directory')
  .option('-v, --verbose', 'Verbose output')
  .option('-o, --output <file>', 'Output file for report')
  .option('--strict', 'Treat all issues as failures (exit 1)')
  .option('--ci', 'CI mode (no color, exit codes only)')
  .action(async (targetPath, options) => {
    try {
      if (!options.ci) logger.info(`Scanning Helm charts in: ${targetPath}`);
      const results = await scanHelm(targetPath, { strict: options.strict });
      await generateReport(results, options.output);

      if (!options.ci) {
        const score = results.score ?? 'N/A';
        const issueCount = results.issues.length;
        logger.info(`✅ Helm scan completed — ${issueCount} issue(s) found, score: ${score}`);
      }

      const hasHigh = results.issues.some((i: any) => i.type === 'high');
      const fail = options.strict ? results.issues.length > 0 : hasHigh;
      process.exit(fail ? 1 : 0);
    } catch (error) {
      logger.error('❌ Helm scan failed:', error);
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

program
  .command('fix')
  .description('Auto-fix security issues in MCP config files')
  .option('--dry-run', 'Show what would change without writing (default)', true)
  .option('--in-place', 'Apply fixes directly to config files')
  .option('-o, --output <file>', 'Write fixed config to a specific file')
  .option('-q, --quiet', 'Minimal output')
  .addHelpText('after', '\nExamples:\n  mcp-audit fix              # Show fixes (dry run)\n  mcp-audit fix --in-place   # Apply fixes to config files\n  mcp-audit fix -o fixed.json # Write fixed config to file')
  .action(async (options) => {
    try {
      logger.info('Running MCP config auto-fix...');
      const results = await autoFixConfig({
        dryRun: !options.inPlace,
        inPlace: options.inPlace,
        output: options.output,
        quiet: options.quiet,
      });

      if (results.length === 0) {
        logger.info('✅ No fixable issues found — config looks good!');
        process.exit(0);
      }

      const totalFixes = results.reduce((sum, r) => sum + r.fixesApplied.length, 0);

      if (!options.quiet) {
        printFixDiff(results);
      }

      if (!options.inPlace && !options.output) {
        console.log(chalk.dim(`\n  Run with --in-place to apply, or -o <file> to save to a new file`));
      }

      logger.info(`${options.inPlace ? '✅' : '🔍'} ${totalFixes} fix(es) across ${results.length} file(s)`);
      process.exit(0);
    } catch (error) {
      logger.error('❌ Auto-fix failed:', error);
      process.exit(1);
    }
  });

program.parse();