import fs from 'fs-extra';
import path from 'path';
import yaml from 'js-yaml';
import { loadConfig } from '../config/config-loader';
import { logger } from '../utils/logger';
import { SecurityResult } from '../types/security-result';

interface MCPConfig {
  servers?: Array<{
    command: string;
    args?: string[];
    env?: Record<string, string>;
  }>;
  mcpServers?: Record<string, any>;
}

export interface SecurityIssue {
  type: 'high' | 'medium' | 'low';
  category: 'permissions' | 'config' | 'filesystem';
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
  '~/.cursor/mcp.json'
];

export async function scanConfig(config: any, verbose = false): Promise<SecurityResult> {
  logger.info('Starting MCP configuration scan...');
  
  const result: ConfigScanResult = {
    configFiles: [],
    issues: [],
    permissions: {
      fileAccess: [],
      networkAccess: false,
      environmentVariables: {}
    },
    score: 100
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
      highRiskIssues: result.issues.filter(i => i.type === 'high').length,
      mediumRiskIssues: result.issues.filter(i => i.type === 'medium').length,
      lowRiskIssues: result.issues.filter(i => i.type === 'low').length
    }
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

  } catch (error) {
    logger.error(`Error analyzing config file ${configPath}:`, error);
    result.issues.push({
      type: 'high',
      category: 'config',
      title: 'Invalid Configuration',
      description: `Could not parse MCP configuration file: ${configPath}`,
      recommendation: 'Check file syntax and ensure it contains valid JSON/YAML',
      evidence: error instanceof Error ? error.message : String(error)
    });
  }
}

function analyzeServers(config: MCPConfig, result: ConfigScanResult, configPath: string): void {
  // Handle different config formats
  const servers = config.servers || config.mcpServers || [];

  if (!Array.isArray(servers) && typeof servers === 'object') {
    Object.values(servers).forEach((server: any) => {
      analyzeServer(server, result, configPath);
    });
  } else if (Array.isArray(servers)) {
    servers.forEach((server) => {
      analyzeServer(server, result, configPath);
    });
  }
}

function analyzeServer(server: any, result: ConfigScanResult, configPath: string): void {
  const command = server.command || '';
  const args = server.args || [];

  // Check for potentially dangerous commands
  if (command.includes('python') || command.includes('node') || command.includes('bash') || command.includes('sh')) {
    result.issues.push({
      type: 'high',
      category: 'permissions',
      title: 'Executable Server Command',
      description: `MCP server uses executable command: ${command}`,
      recommendation: 'Review server implementation for security vulnerabilities',
      evidence: `Command: ${command}, Args: ${JSON.stringify(args)}`
    });
    result.score -= 20;
  }

  // Check for unrestricted file access
  if (command.includes('fs') || args.some((arg: string) => arg.includes('*') || arg.includes('/'))) {
    result.issues.push({
      type: 'medium',
      category: 'filesystem',
      title: 'File System Access',
      description: 'Server requests file system access',
      recommendation: 'Restrict to specific directories using allowedFileAccess in config',
      evidence: `Command: ${command}, Args: ${JSON.stringify(args)}`
    });
    result.score -= 15;
  }

  // Check environment variables
  if (server.env && Object.keys(server.env).length > 0) {
    Object.entries(server.env).forEach(([key, value]) => {
      result.permissions.environmentVariables[key] = value as string;
      
      if (key.includes('SECRET') || key.includes('KEY') || key.includes('PASSWORD')) {
        result.issues.push({
          type: 'high',
          category: 'config',
          title: 'Environment Variable with Sensitive Data',
          description: `Environment variable ${key} may contain sensitive data`,
          recommendation: 'Use secure secrets management instead of environment variables',
          evidence: `Variable: ${key}, Value: ${value}`
        });
        result.score -= 25;
      }
    });
  }

  // Check for network access
  if (command.includes('http') || command.includes('curl') || command.includes('wget')) {
    result.permissions.networkAccess = true;
    result.issues.push({
      type: 'medium',
      category: 'permissions',
      title: 'Network Access',
      description: 'Server has network capabilities',
      recommendation: 'Ensure server origin is trusted and network usage is justified',
      evidence: `Command: ${command}`
    });
    result.score -= 10;
  }
}

function calculateSecurityScore(result: ConfigScanResult): void {
  // Ensure score doesn't go below 0
  result.score = Math.max(0, result.score);
}

function expandPath(p: string): string {
  if (p.startsWith('~/')) {
    return path.join(process.env.HOME || '', p.slice(2));
  }
  return p;
}

