import fs from 'fs-extra';
import path from 'path';
import { homedir } from 'os';

export interface MCPAuditConfig {
  vulnerabilityDatabase: string;
  trustWeight: {
    stars: number;
    tests: number;
    ci: number;
    age: number;
  };
  allowedFileAccess: string[];
  scanDepth: number;
  excludePatterns: string[];
}

const DEFAULT_CONFIG: MCPAuditConfig = {
  vulnerabilityDatabase: 'https://raw.githubusercontent.com/sulthonzh/mcp-vulnerability-database/main/database.json',
  trustWeight: {
    stars: 0.3,
    tests: 0.3,
    ci: 0.2,
    age: 0.2
  },
  allowedFileAccess: [
    '~/documents',
    '~/projects',
    '~/downloads'
  ],
  scanDepth: 2,
  excludePatterns: [
    'node_modules/**',
    'dist/**',
    'build/**',
    '**/*.log',
    '**/*.tmp'
  ]
};

export function getConfigPath(): string {
  return path.join(process.cwd(), 'mcp-audit.config.json');
}

export function getDefaultConfigPath(): string {
  return path.join(homedir(), '.mcp-audit.json');
}

export function loadConfig(configPath?: string): MCPAuditConfig {
  const configFile = configPath || getConfigPath();
  
  if (fs.existsSync(configFile)) {
    try {
      const userConfig = fs.readJsonSync(configFile);
      return { ...DEFAULT_CONFIG, ...userConfig };
    } catch (error) {
      console.warn(`Warning: Could not parse config file ${configFile}, using defaults`);
      return DEFAULT_CONFIG;
    }
  }
  
  // Check for global config
  const globalConfigFile = getDefaultConfigPath();
  if (fs.existsSync(globalConfigFile)) {
    try {
      const globalConfig = fs.readJsonSync(globalConfigFile);
      return { ...DEFAULT_CONFIG, ...globalConfig };
    } catch (error) {
      console.warn(`Warning: Could not parse global config file ${globalConfigFile}, using defaults`);
    }
  }
  
  return DEFAULT_CONFIG;
}

export async function initializeConfig(configPath?: string): Promise<void> {
  const configFile = configPath || getConfigPath();
  const config = loadConfig();
  
  await fs.writeJson(configFile, config, { spaces: 2 });
  console.log(`Configuration initialized at: ${configFile}`);
}