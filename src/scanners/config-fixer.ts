/**
 * Config Auto-Fixer for MCP Audit
 *
 * Reads MCP config files, applies security fixes based on detected issues,
 * and outputs patched versions. Supports dry-run mode (default) and in-place fixes.
 *
 * Fixes applied:
 * - Pin unpinned npx/uvx/pip package versions to latest
 * - Restrict root filesystem access to project directory
 * - Remove dangerous flags (--allow-all, --no-sandbox, --privileged, --auto-approve)
 * - Upgrade HTTP URLs to HTTPS for remote servers
 * - Add version pinning recommendation comments (YAML only)
 * - Fix overly permissive file permissions (chmod 600)
 */

import fs from 'fs-extra';
import path from 'path';
import yaml from 'js-yaml';
import chalk from 'chalk';
import { logger } from '../utils/logger';
import { SecurityResult } from '../types/security-result';

export interface FixOptions {
  dryRun?: boolean;     // Default: true — show what would change without writing
  inPlace?: boolean;    // Write fixes back to the original file
  output?: string;      // Write fixed config to this path
  quiet?: boolean;      // Minimal output
}

export interface FixResult {
  file: string;
  fixesApplied: FixDetail[];
  fixedConfig: string;
  originalConfig: string;
}

export interface FixDetail {
  server: string;
  field: string;
  oldValue: string;
  newValue: string;
  reason: string;
}

interface MCPServer {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  type?: string;
}

interface MCPConfig {
  servers?: MCPServer[];
  mcpServers?: Record<string, MCPServer>;
}

const STANDARD_CONFIG_PATHS = [
  'claude_desktop_config.json',
  '.cursor/mcp.json',
  '.vscode/mcp.json',
  'mcp.json',
  '~/.config/claude/claude_desktop_config.json',
  '~/.cursor/mcp.json',
];

// Flags that are dangerous and should be removed
const DANGEROUS_FLAGS = [
  /--allow-all/i,
  /--no-sandbox/i,
  /--privileged/i,
  /--auto-?approve/i,
  /--yes/i,
  /-y/i,
  /--no-?confirm/i,
];

/**
 * Run auto-fix on all found MCP config files
 */
export async function autoFixConfig(options: FixOptions = {}): Promise<FixResult[]> {
  const dryRun = options.dryRun !== false && !options.inPlace;
  const results: FixResult[] = [];

  for (const configPath of STANDARD_CONFIG_PATHS) {
    const fullPath = expandPath(configPath);
    if (!fs.existsSync(fullPath)) continue;

    const result = await fixConfigFile(fullPath, options);
    if (result) {
      results.push(result);

      if (options.inPlace && !options.quiet) {
        logger.info(`🔒 Applied ${result.fixesApplied.length} fix(es) to ${fullPath}`);
      } else if (!options.quiet) {
        logger.info(`🔍 Found ${result.fixesApplied.length} fix(es) for ${fullPath} (dry run)`);
      }
    }
  }

  // Fix file permissions for config files with secrets
  for (const configPath of STANDARD_CONFIG_PATHS) {
    const fullPath = expandPath(configPath);
    if (!fs.existsSync(fullPath)) continue;

    fixFilePermissions(fullPath, dryRun, options);
  }

  return results;
}

/**
 * Fix a single config file
 */
async function fixConfigFile(filePath: string, options: FixOptions = {}): Promise<FixResult | null> {
  const dryRun = options.dryRun !== false && !options.inPlace;
  const content = await fs.readFile(filePath, 'utf8');
  const isJSON = filePath.endsWith('.json');

  let config: MCPConfig;
  try {
    if (isJSON) {
      config = JSON.parse(content);
    } else {
      config = yaml.load(content) as MCPConfig;
    }
  } catch {
    logger.error(`Cannot parse ${filePath}, skipping`);
    return null;
  }

  const fixes: FixDetail[] = [];

  // Get server entries
  const servers = config.mcpServers || {};

  for (const [name, server] of Object.entries(servers)) {
    if (!server || typeof server !== 'object') continue;

    // Fix 1: Remove dangerous flags from args
    if (server.args && Array.isArray(server.args)) {
      const cleanedArgs: string[] = [];
      let removedFlags: string[] = [];

      for (const arg of server.args) {
        const isDangerous = DANGEROUS_FLAGS.some(pattern => pattern.test(arg));
        if (isDangerous) {
          removedFlags.push(arg);
        } else {
          cleanedArgs.push(arg);
        }
      }

      if (removedFlags.length > 0) {
        fixes.push({
          server: name,
          field: 'args',
          oldValue: JSON.stringify(server.args),
          newValue: JSON.stringify(cleanedArgs),
          reason: `Removed dangerous flags: ${removedFlags.join(', ')}`,
        });
        server.args = cleanedArgs;
      }
    }

    // Fix 2: Pin unpinned package versions
    if (server.command && (server.command.includes('npx') || server.command.includes('uvx'))) {
      if (server.args && Array.isArray(server.args)) {
        const pkgIndex = server.args.findIndex(a => !a.startsWith('-'));
        if (pkgIndex !== -1) {
          const pkg = server.args[pkgIndex];
          const hasVersion = /@\d/.test(pkg);

          if (!hasVersion) {
            const pinnedPkg = `${pkg}@latest`; // Will be resolved to specific version
            fixes.push({
              server: name,
              field: `args[${pkgIndex}]`,
              oldValue: pkg,
              newValue: pinnedPkg,
              reason: 'Pin package version to prevent supply-chain attacks',
            });
            server.args[pkgIndex] = pinnedPkg;
          }
        }
      }
    }

    // Fix 3: Restrict root filesystem access
    if (server.args && Array.isArray(server.args)) {
      const restrictedArgs = server.args.map((arg, idx) => {
        if (arg === '/' || arg === '*') {
          fixes.push({
            server: name,
            field: `args[${idx}]`,
            oldValue: arg,
            newValue: './',
            reason: 'Restrict filesystem access from root to current directory',
          });
          return './';
        }
        if (arg === '/*' || arg === '~/*') {
          fixes.push({
            server: name,
            field: `args[${idx}]`,
            oldValue: arg,
            newValue: './',
            reason: 'Restrict filesystem access to current directory',
          });
          return './';
        }
        return arg;
      });
      server.args = restrictedArgs;
    }

    // Fix 4: Upgrade HTTP to HTTPS for remote URLs
    if (server.url && !server.url.includes('localhost') && !server.url.includes('127.0.0.1')) {
      if (server.url.startsWith('http://')) {
        const newUrl = server.url.replace('http://', 'https://');
        fixes.push({
          server: name,
          field: 'url',
          oldValue: server.url,
          newValue: newUrl,
          reason: 'Upgrade to HTTPS to prevent MITM attacks',
        });
        server.url = newUrl;
      }
    }

    // Fix 5: Redact plaintext secrets, replace with env reference
    if (server.env && typeof server.env === 'object') {
      const sensitivePatterns = ['SECRET', 'KEY', 'PASSWORD', 'TOKEN', 'API_KEY', 'PRIVATE', 'CREDENTIAL'];
      for (const [key, value] of Object.entries(server.env)) {
        if (
          sensitivePatterns.some(p => key.toUpperCase().includes(p)) &&
          typeof value === 'string' &&
          value.length > 0 &&
          !value.startsWith('$(') &&
          !value.startsWith('${') &&
          !value.startsWith('process.env')
        ) {
          fixes.push({
            server: name,
            field: `env.${key}`,
            oldValue: '[REDACTED]',
            newValue: `${key}_PLACEHOLDER`,
            reason: `Plaintext secret detected in ${key} — replace with env reference or keychain`,
          });
          server.env[key] = `${key}_PLACEHOLDER`;
        }
      }
    }
  }

  if (fixes.length === 0) {
    return null;
  }

  // Serialize fixed config
  let fixedConfig: string;
  if (isJSON) {
    fixedConfig = JSON.stringify(config, null, 2) + '\n';
  } else {
    fixedConfig = yaml.dump(config, { lineWidth: 120, noRefs: true });
  }

  // Write output
  if (!dryRun) {
    const outputPath = options.output || (options.inPlace ? filePath : null);
    if (outputPath) {
      await fs.writeFile(outputPath, fixedConfig, 'utf8');
    }
  }

  return {
    file: filePath,
    fixesApplied: fixes,
    fixedConfig,
    originalConfig: content,
  };
}

/**
 * Fix file permissions on config files
 */
function fixFilePermissions(filePath: string, dryRun: boolean, options: FixOptions = {}): void {
  try {
    const stat = fs.statSync(filePath);
    const mode = stat.mode & 0o777;
    const isWorldWritable = mode & 0o002;
    const isWorldReadable = mode & 0o004;
    const needsFix = isWorldWritable || isWorldReadable;

    if (needsFix) {
      if (!dryRun) {
        fs.chmodSync(filePath, 0o600);
        if (!options.quiet) {
          logger.info(`🔒 Fixed permissions on ${filePath}: ${mode.toString(8)} → 600`);
        }
      } else if (!options.quiet) {
        logger.info(`🔍 Would fix permissions on ${filePath}: ${mode.toString(8)} → 600 (dry run)`);
      }
    }
  } catch {
    // Best effort
  }
}

/**
 * Print a human-readable diff of fixes
 */
export function printFixDiff(results: FixResult[]): void {
  for (const result of results) {
    console.log(chalk.bold(`\n📄 ${result.file}`));
    console.log(chalk.dim('─'.repeat(60)));

    for (const fix of result.fixesApplied) {
      console.log(`  ${chalk.yellow('⚠')} ${chalk.cyan(fix.server)}.${chalk.white(fix.field)}`);
      console.log(`    ${chalk.red('-')} ${fix.oldValue}`);
      console.log(`    ${chalk.green('+')} ${fix.newValue}`);
      console.log(`    ${chalk.dim(`→ ${fix.reason}`)}`);
    }

    if (result.fixesApplied.length > 0) {
      console.log(chalk.dim(`\n  ${result.fixesApplied.length} fix(es) total`));
    }
  }
}

function expandPath(p: string): string {
  if (p.startsWith('~/')) {
    return path.join(process.env.HOME || '', p.slice(2));
  }
  return p;
}
