import fs from 'fs-extra';
import path from 'path';
import yaml from 'js-yaml';
import { logger } from '../utils/logger';
import { SecurityResult } from '../types/security-result';

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

export interface SecurityIssue {
  type: 'high' | 'medium' | 'low';
  category: 'permissions' | 'config' | 'filesystem' | 'network' | 'injection' | 'supply-chain' | 'transport';
  title: string;
  description: string;
  recommendation: string;
  evidence?: string;
}

interface ConfigScanResult {
  configFiles: string[];
  issues: SecurityIssue[];
  permissions: {
    fileAccess: string[];
    networkAccess: boolean;
    environmentVariables: Record<string, string>;
  };
  score: number;
}

const STANDARD_CONFIG_PATHS = [
  'claude_desktop_config.json',
  '.cursor/mcp.json',
  '.vscode/mcp.json',
  'mcp.json',
  '~/.config/claude/claude_desktop_config.json',
  '~/.cursor/mcp.json',
];

// Known dangerous argument patterns
const DANGEROUS_ARGS = [
  { pattern: /--allow-all/i, title: 'Allow-All Flag', severity: 'high' as const },
  { pattern: /--no-sandbox/i, title: 'Sandbox Disabled', severity: 'high' as const },
  { pattern: /--privileged/i, title: 'Privileged Mode', severity: 'high' as const },
  { pattern: /eval/i, title: 'Code Evaluation', severity: 'high' as const },
  { pattern: /exec/i, title: 'Code Execution', severity: 'medium' as const },
  { pattern: /\$\(/i, title: 'Command Substitution', severity: 'high' as const },
  { pattern: /\|\|/i, title: 'Shell Pipe Chain', severity: 'medium' as const },
  { pattern: /&&/i, title: 'Shell Command Chain', severity: 'medium' as const },
  { pattern: /\.\.\/\.\.\//i, title: 'Path Traversal', severity: 'high' as const },
];

// Known safe MCP server packages
const KNOWN_SAFE_PACKAGES = new Set([
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-fetch',
]);

export async function scanConfig(config: unknown, verbose = false): Promise<SecurityResult> {
  logger.info('Starting MCP configuration scan...');

  const result: ConfigScanResult = {
    configFiles: [],
    issues: [],
    permissions: {
      fileAccess: [],
      networkAccess: false,
      environmentVariables: {},
    },
    score: 100,
  };

  // Find and analyze MCP config files
  for (const configPath of STANDARD_CONFIG_PATHS) {
    const fullPath = expandPath(configPath);

    if (fs.existsSync(fullPath)) {
      result.configFiles.push(fullPath);
      await analyzeConfigFile(fullPath, result);
    }
  }

  // Calculate security score
  calculateSecurityScore(result);

  const securityResult: SecurityResult = {
    scanType: 'config',
    timestamp: new Date().toISOString(),
    target: 'local configuration',
    issues: result.issues,
    score: result.score,
    summary: {
      configFilesFound: result.configFiles.length,
      highRiskIssues: result.issues.filter((i) => i.type === 'high').length,
      mediumRiskIssues: result.issues.filter((i) => i.type === 'medium').length,
      lowRiskIssues: result.issues.filter((i) => i.type === 'low').length,
    },
  };

  if (verbose) {
    logger.debug('Detailed scan results:', result);
  }

  return securityResult;
}

async function analyzeConfigFile(configPath: string, result: ConfigScanResult): Promise<void> {
  try {
    const content = await fs.readFile(configPath, 'utf8');
    let config: MCPConfig;

    if (configPath.endsWith('.json')) {
      config = JSON.parse(content);
    } else if (configPath.endsWith('.yaml') || configPath.endsWith('.yml')) {
      config = yaml.load(content) as MCPConfig;
    } else {
      logger.warn(`Unsupported config file format: ${configPath}`);
      return;
    }

    analyzeServers(config, result, configPath);

    // Check file permissions
    checkFilePermissions(configPath, result);
  } catch (error) {
    logger.error(`Error analyzing config file ${configPath}:`, error);
    result.issues.push({
      type: 'high',
      category: 'config',
      title: 'Invalid Configuration',
      description: `Could not parse MCP configuration file: ${configPath}`,
      recommendation: 'Check file syntax and ensure it contains valid JSON/YAML',
      evidence: error instanceof Error ? error.message : String(error),
    });
  }
}

function analyzeServers(config: MCPConfig, result: ConfigScanResult, configPath: string): void {
  const servers = config.servers || config.mcpServers || [];

  if (!Array.isArray(servers) && typeof servers === 'object') {
    Object.entries(servers).forEach(([name, server]) => {
      analyzeServer(server, result, configPath, name);
    });
  } else if (Array.isArray(servers)) {
    servers.forEach((server, i) => {
      analyzeServer(server, result, configPath, `server-${i}`);
    });
  }
}

function analyzeServer(server: MCPServer, result: ConfigScanResult, configPath: string, name: string): void {
  const command = server.command || '';
  const args = server.args || [];
  const fullCommand = `${command} ${args.join(' ')}`;

  // Check if this is a known safe package
  const isKnownSafe = KNOWN_SAFE_PACKAGES.has(command) || args.some((a) => KNOWN_SAFE_PACKAGES.has(a));

  // === Runtime Interpreter Detection ===
  if (command.includes('npx') || command.includes('node')) {
    result.issues.push({
      type: isKnownSafe ? 'low' : 'high',
      category: 'permissions',
      title: isKnownSafe ? 'Standard Node.js MCP Server' : 'Unverified Node.js Server',
      description: isKnownSafe
        ? `Server "${name}" uses a known official MCP package: ${command}`
        : `Server "${name}" runs via ${command} — any npm package can execute arbitrary code`,
      recommendation: isKnownSafe
        ? 'This is a known safe package, but still review the version'
        : 'Verify the package source, check npm page, review recent versions for supply-chain attacks',
      evidence: `Command: ${command}, Args: ${JSON.stringify(args)}`,
    });
    result.score -= isKnownSafe ? 2 : 20;
  }

  if (command.includes('python') || command.includes('uvx') || command.includes('pip')) {
    result.issues.push({
      type: isKnownSafe ? 'low' : 'high',
      category: 'permissions',
      title: isKnownSafe ? 'Standard Python MCP Server' : 'Unverified Python Server',
      description: `Server "${name}" runs via ${command} — can execute arbitrary Python code`,
      recommendation: 'Verify the package is from a trusted source and pin the version',
      evidence: `Command: ${command}, Args: ${JSON.stringify(args)}`,
    });
    result.score -= isKnownSafe ? 2 : 20;
  }

  if (command.includes('bash') || command.includes('sh') || command.includes('zsh')) {
    result.issues.push({
      type: 'high',
      category: 'injection',
      title: 'Shell Command Execution',
      description: `Server "${name}" directly executes shell commands — highest risk for command injection`,
      recommendation: 'Avoid shell-based MCP servers. If needed, use with strict sandboxing',
      evidence: `Command: ${command}, Args: ${JSON.stringify(args)}`,
    });
    result.score -= 30;
  }

  // === Dangerous Argument Patterns ===
  for (const dangerous of DANGEROUS_ARGS) {
    if (dangerous.pattern.test(fullCommand)) {
      result.issues.push({
        type: dangerous.severity,
        category: 'injection',
        title: dangerous.title,
        description: `Server "${name}" has dangerous argument matching "${dangerous.pattern}"`,
        recommendation: 'Review if this flag is necessary and what it exposes',
        evidence: `Full command: ${fullCommand}`,
      });
      result.score -= dangerous.severity === 'high' ? 25 : 15;
    }
  }

  // === Environment Variable Secrets ===
  if (server.env && Object.keys(server.env).length > 0) {
    for (const [key, value] of Object.entries(server.env)) {
      result.permissions.environmentVariables[key] = value;

      const sensitivePatterns = ['SECRET', 'KEY', 'PASSWORD', 'TOKEN', 'API_KEY', 'PRIVATE', 'CREDENTIAL'];
      if (sensitivePatterns.some((p) => key.toUpperCase().includes(p))) {
        const isPlaintext = typeof value === 'string' && value.length > 0 && !value.startsWith('$(');
        result.issues.push({
          type: isPlaintext ? 'high' : 'medium',
          category: 'config',
          title: isPlaintext ? 'Plaintext Secret in Config' : 'Secret Reference in Config',
          description: isPlaintext
            ? `Server "${name}" has a plaintext secret in ${key} — this file may be readable by other processes`
            : `Server "${name}" references a secret via ${key}`,
          recommendation: isPlaintext
            ? 'Use system keychain, vault, or at minimum ensure config file has restricted permissions (chmod 600)'
            : 'Good practice referencing secrets, ensure the resolver is secure',
          evidence: `Variable: ${key}=${isPlaintext ? '[REDACTED]' : value}`,
        });
        result.score -= isPlaintext ? 25 : 5;
      }
    }
  }

  // === Filesystem Access Patterns ===
  const fsPatterns = ['/home', '/etc', '/var', '/root', '/Users', '~/', '/tmp'];
  const hasFsArgs = args.some((arg) => {
    const argStr = String(arg);
    if (fsPatterns.some((p) => argStr.includes(p))) return true;
    if (argStr === '/' || argStr === '*') return true;
    if (argStr.includes('/*')) return true;
    return false;
  });

  if (hasFsArgs) {
    const isRoot = args.some((arg) => arg === '/' || arg === '*' || arg.includes('/*'));
    result.issues.push({
      type: isRoot ? 'high' : 'medium',
      category: 'filesystem',
      title: isRoot ? 'Root Filesystem Access' : 'Broad Filesystem Access',
      description: isRoot
        ? `Server "${name}" has access to the entire filesystem — any file can be read/written`
        : `Server "${name}" has filesystem access that may include sensitive directories`,
      recommendation: isRoot
        ? 'Restrict to specific project directories only'
        : 'Review if all directories are necessary',
      evidence: `Args: ${args.join(', ')}`,
    });
    result.score -= isRoot ? 25 : 10;
  }

  // === Network/URL-based Servers ===
  if (server.url) {
    result.permissions.networkAccess = true;
    const isLocalhost = server.url.includes('localhost') || server.url.includes('127.0.0.1');
    const isHttps = server.url.startsWith('https://');

    if (!isLocalhost && !isHttps) {
      result.issues.push({
        type: 'high',
        category: 'network',
        title: 'Insecure Remote Server',
        description: `Server "${name}" connects to a remote server over plain HTTP`,
        recommendation: 'Use HTTPS to prevent MITM attacks on MCP communication',
        evidence: `URL: ${server.url}`,
      });
      result.score -= 20;
    } else if (!isLocalhost) {
      result.issues.push({
        type: 'low',
        category: 'network',
        title: 'Remote MCP Server',
        description: `Server "${name}" connects to a remote server — your prompts and tool results travel over the network`,
        recommendation: 'Ensure you trust the remote server operator',
        evidence: `URL: ${server.url}`,
      });
      result.score -= 3;
    }
  }

  // === Network Access via Command ===
  if (command.includes('http') || command.includes('curl') || command.includes('wget') || command.includes('fetch')) {
    result.permissions.networkAccess = true;
    result.issues.push({
      type: 'medium',
      category: 'network',
      title: 'Network Access',
      description: `Server "${name}" has network capabilities via ${command}`,
      recommendation: 'Ensure server origin is trusted and network usage is justified',
      evidence: `Command: ${command}`,
    });
    result.score -= 10;
  }

  // === Transport Security ===
  if (server.type === 'sse' || (server.url && !server.url.includes('localhost') && !server.url.includes('127.0.0.1'))) {
    if (server.url && !server.url.startsWith('https://')) {
      result.issues.push({
        type: 'high',
        category: 'transport',
        title: 'Insecure SSE Transport',
        description: `Server "${name}" uses SSE transport over unencrypted connection — prompts and tool results can be intercepted`,
        recommendation: 'Use wss:// or https:// for SSE transport to protect MCP messages in transit',
        evidence: `Transport: ${server.type || 'sse'}, URL: ${server.url}`,
      });
      result.score -= 20;
    }
    if (server.type === 'sse') {
      result.issues.push({
        type: 'medium',
        category: 'transport',
        title: 'SSE Transport Without Auth',
        description: `Server "${name}" uses SSE transport — verify it requires authentication to prevent unauthorized tool invocation`,
        recommendation: 'Add API key, Bearer token, or mTLS authentication to SSE endpoints',
        evidence: `URL: ${server.url}`,
      });
      result.score -= 10;
    }
  }

  // === Supply Chain: Version Pinning ===
  if (command.includes('npx') || command.includes('uvx') || command.includes('pip')) {
    const hasVersion = args.some((a) => /@\d|^\d|^v\d/.test(String(a)) || String(a).includes('==') || String(a).includes('>='));
    if (!hasVersion) {
      const pkgArg = args.find((a) => !a.startsWith('-'));
      result.issues.push({
        type: 'medium',
        category: 'supply-chain',
        title: 'Unpinned Package Version',
        description: `Server "${name}" runs ${pkgArg || 'a package'} without a pinned version — a malicious update could compromise your system`,
        recommendation: `Pin the version: npx ${pkgArg}@1.2.3 or uvx ${pkgArg}==1.2.3`,
        evidence: `Command: ${command} ${args.join(' ')}`,
      });
      result.score -= 15;
    }
  }

  // === Supply Chain: Local/Relative Path Execution ===
  if (command.startsWith('.') || command.startsWith('/') || args.some((a) => String(a).startsWith('./') || String(a).startsWith('../'))) {
    result.issues.push({
      type: 'medium',
      category: 'supply-chain',
      title: 'Local Path Execution',
      description: `Server "${name}" runs from a local path — ensure the code is from a trusted source and hasn't been tampered with`,
      recommendation: 'Verify the source code integrity of local MCP servers',
      evidence: `Command: ${command}, Args: ${args.join(' ')}`,
    });
    result.score -= 8;
  }

  // === Prompt Injection Risk: Auto-approve Patterns ===
  if (args.some((a) => /--auto-?approve|--yes|-y|--no-?confirm/i.test(String(a)))) {
    result.issues.push({
      type: 'high',
      category: 'permissions',
      title: 'Auto-Approve Enabled',
      description: `Server "${name}" has auto-approve flags — tool calls execute without user confirmation`,
      recommendation: 'Remove auto-approve flags and review each tool call manually',
      evidence: `Full command: ${fullCommand}`,
    });
    result.score -= 25;
  }
}

function checkFilePermissions(configPath: string, result: ConfigScanResult): void {
  try {
    const stat = fs.statSync(configPath);
    const mode = stat.mode & 0o777;
    const isWorldReadable = mode & 0o004;
    const isGroupWritable = mode & 0o020;
    const isWorldWritable = mode & 0o002;

    if (isWorldWritable) {
      result.issues.push({
        type: 'high',
        category: 'config',
        title: 'World-Writable Config File',
        description: `${configPath} is world-writable — any user on this system can modify your MCP configuration`,
        recommendation: 'Run: chmod 600 <config-file> to restrict access',
        evidence: `File mode: ${mode.toString(8)}`,
      });
      result.score -= 20;
    } else if (isGroupWritable) {
      result.issues.push({
        type: 'medium',
        category: 'config',
        title: 'Group-Writable Config File',
        description: `${configPath} is group-writable — group members can modify your MCP configuration`,
        recommendation: 'Run: chmod 600 <config-file> for stricter access',
        evidence: `File mode: ${mode.toString(8)}`,
      });
      result.score -= 10;
    }

    if (isWorldReadable) {
      // Only flag if config contains secrets
      const hasSecrets = result.issues.some((i) => i.title.includes('Plaintext Secret'));
      if (hasSecrets) {
        result.issues.push({
          type: 'medium',
          category: 'config',
          title: 'World-Readable Config With Secrets',
          description: `${configPath} is world-readable and contains secrets — other users can read your API keys`,
          recommendation: 'Run: chmod 600 <config-file>',
          evidence: `File mode: ${mode.toString(8)}`,
        });
        result.score -= 15;
      }
    }
  } catch {
    // Permission check is best-effort, skip on error
  }
}

function calculateSecurityScore(result: ConfigScanResult): void {
  result.score = Math.max(0, Math.min(100, result.score));
}

function expandPath(p: string): string {
  if (p.startsWith('~/')) {
    return path.join(process.env.HOME || '', p.slice(2));
  }
  return p;
}
