import { Octokit } from '@octokit/rest';
import simpleGit from 'simple-git';
import fs from 'fs-extra';
import path from 'path';
import { loadConfig } from '../config/config-loader';
import { logger } from '../utils/logger';
import { SecurityResult, SecurityIssue } from '../types/security-result';

interface RepositoryInfo {
  url: string;
  owner: string;
  repo: string;
  clonePath: string;
  stars: number;
  hasTests: boolean;
  hasCI: boolean;
  ageInDays: number;
  description?: string;
}

export interface ScanOptions {
  scanDepth: number;
  vulnerabilityDatabase: string;
  trustWeight: {
    stars: number;
    tests: number;
    ci: number;
    age: number;
  };
}

export async function checkServer(repository: string, options: ScanOptions, verbose = false): Promise<SecurityResult> {
  logger.info(`Analyzing MCP server: ${repository}`);

  const repoInfo = await parseRepositoryUrl(repository);
  if (!repoInfo) {
    throw new Error(`Invalid repository URL: ${repository}`);
  }

  const result: SecurityResult = {
    scanType: 'server',
    timestamp: new Date().toISOString(),
    target: repository,
    issues: [],
    score: 0,
    summary: {
      configFilesFound: 0,
      highRiskIssues: 0,
      mediumRiskIssues: 0,
      lowRiskIssues: 0
    }
  };

  try {
    // Clone repository
    const clonePath = await cloneRepository(repoInfo);
    
    // Analyze repository
    const analysis = await analyzeRepository(clonePath, options);
    
    // Calculate trust score
    result.score = calculateTrustScore(analysis, options.trustWeight);
    
    // Analyze code for vulnerabilities
    const vulnerabilities = await analyzeCodeForVulnerabilities(clonePath, options.scanDepth);
    result.issues.push(...vulnerabilities);
    
    // Update summary
    result.summary.highRiskIssues = result.issues.filter(i => i.type === 'high').length;
    result.summary.mediumRiskIssues = result.issues.filter(i => i.type === 'medium').length;
    result.summary.lowRiskIssues = result.issues.filter(i => i.type === 'low').length;
    
    // Cleanup
    await fs.remove(clonePath);
    
    if (verbose) {
      logger.debug('Repository analysis completed:', analysis);
    }

  } catch (error) {
    logger.error(`Error analyzing repository ${repository}:`, error);
    result.issues.push({
      type: 'high',
      category: 'config',
      title: 'Repository Analysis Failed',
      description: `Could not analyze repository: ${repository}`,
      recommendation: 'Check repository accessibility and ensure it contains valid MCP server code',
      evidence: error instanceof Error ? error.message : String(error)
    });
    result.score = 0;
  }

  return result;
}

async function parseRepositoryUrl(url: string): Promise<RepositoryInfo | null> {
  let owner: string, repo: string;
  
  if (url.startsWith('https://github.com/')) {
    const parts = url.replace('https://github.com/', '').split('/');
    if (parts.length >= 2) {
      owner = parts[0];
      repo = parts[1].replace('.git', '');
      return {
        url,
        owner,
        repo,
        clonePath: path.join(process.cwd(), 'temp-clones', `${owner}-${repo}`),
        stars: 0,
        hasTests: false,
        hasCI: false,
        ageInDays: 0
      };
    }
  } else if (url.startsWith('github.com/')) {
    const parts = url.replace('github.com/', '').split('/');
    if (parts.length >= 2) {
      owner = parts[0];
      repo = parts[1].replace('.git', '');
      return {
        url: `https://github.com/${owner}/${repo}`,
        owner,
        repo,
        clonePath: path.join(process.cwd(), 'temp-clones', `${owner}-${repo}`),
        stars: 0,
        hasTests: false,
        hasCI: false,
        ageInDays: 0
      };
    }
  } else if (path.isAbsolute(url)) {
    // Local path
    const stats = await fs.stat(url);
    if (stats.isDirectory()) {
      return {
        url: `local:${url}`,
        owner: 'local',
        repo: path.basename(url),
        clonePath: url,
        stars: 0,
        hasTests: false,
        hasCI: false,
        ageInDays: 0
      };
    }
  }
  
  return null;
}

async function cloneRepository(repoInfo: RepositoryInfo): Promise<string> {
  if (repoInfo.url.startsWith('local:')) {
    return repoInfo.clonePath;
  }

  try {
    await fs.ensureDir(path.dirname(repoInfo.clonePath));
    
    // Get repository info from GitHub API
    const octokit = new Octokit();
    const { data } = await octokit.rest.repos.get({
      owner: repoInfo.owner,
      repo: repoInfo.repo
    });
    
    repoInfo.stars = data.stargazers_count || 0;
    repoInfo.hasTests = data.topics?.includes('tests') || false;
    repoInfo.hasCI = data.has_issues || false;
    repoInfo.ageInDays = Math.floor((Date.now() - new Date(data.created_at).getTime()) / (1000 * 60 * 60 * 24));
    repoInfo.description = data.description || undefined;

    // Clone the repository
    const git = simpleGit();
    await git.clone(repoInfo.url, repoInfo.clonePath);
    
    return repoInfo.clonePath;
  } catch (error) {
    throw new Error(`Failed to clone repository: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function analyzeRepository(clonePath: string, options: ScanOptions): Promise<any> {
  const analysis = {
    hasPackageJson: false,
    hasMCPConfig: false,
    hasTests: false,
    hasCI: false,
    language: 'unknown',
    dependencies: 0,
    files: 0,
    size: 0
  };

  try {
    // Check for package.json
    analysis.hasPackageJson = await fs.pathExists(path.join(clonePath, 'package.json'));
    
    // Check for MCP config files
    const mcpFiles = ['mcp.json', 'claude_desktop_config.json', 'config.json'];
    for (const file of mcpFiles) {
      if (await fs.pathExists(path.join(clonePath, file))) {
        analysis.hasMCPConfig = true;
        break;
      }
    }
    
    // Check for tests
    const testDirs = ['test', 'tests', '__tests__', 'spec', 'specs'];
    for (const dir of testDirs) {
      if (await fs.pathExists(path.join(clonePath, dir))) {
        analysis.hasTests = true;
        break;
      }
    }
    
    // Check for CI files
    const ciFiles = ['.github/workflows', '.gitlab-ci.yml', 'circle.yml', 'travis.yml'];
    for (const file of ciFiles) {
      const filePath = path.join(clonePath, file);
      if (file.includes('workflows') && await fs.pathExists(filePath)) {
        const files = await fs.readdir(filePath);
        analysis.hasCI = files.length > 0;
      } else if (await fs.pathExists(filePath)) {
        analysis.hasCI = true;
      }
    }
    
    // Get repository stats
    const files = await getAllFiles(clonePath);
    analysis.files = files.length;
    analysis.size = await getDirectorySize(clonePath);
    
    // Detect language based on files
    analysis.language = detectLanguage(files);
    
    // Get dependencies count
    if (analysis.hasPackageJson) {
      const packageJson = await fs.readJson(path.join(clonePath, 'package.json'));
      analysis.dependencies = Object.keys(packageJson.dependencies || {}).length + 
                             Object.keys(packageJson.devDependencies || {}).length;
    }

  } catch (error) {
    logger.warn('Error during repository analysis:', error);
  }

  return analysis;
}

async function analyzeCodeForVulnerabilities(clonePath: string, depth: number): Promise<SecurityIssue[]> {
  const vulnerabilities: SecurityIssue[] = [];
  const files = await getAllFiles(clonePath);

  for (const file of files) {
    if (depth > 0 && file.split('/').length > depth) {
      continue; // Skip files beyond scan depth
    }

    const content = await fs.readFile(file, 'utf8');
    const relativePath = path.relative(clonePath, file);

    // Check for hardcoded secrets
    const secrets = checkForSecrets(content);
    secrets.forEach(secret => {
      vulnerabilities.push({
        type: 'high',
        category: 'config',
        title: 'Hardcoded Secret Detected',
        description: `Hardcoded secret found in ${relativePath}`,
        recommendation: 'Use environment variables or secure secrets management',
        evidence: `Secret type: ${secret.type}, Line: ${secret.line}`
      });
    });

    // Check for dangerous functions
    const dangerousFunctions = checkForDangerousFunctions(content);
    dangerousFunctions.forEach(func => {
      vulnerabilities.push({
        type: 'medium',
        category: 'permissions',
        title: 'Dangerous Function Usage',
        description: `Use of potentially dangerous function: ${func}`,
        recommendation: 'Review usage context and ensure proper input validation',
        evidence: `Function: ${func}, File: ${relativePath}`
      });
    });

    // Check for eval usage
    if (content.includes('eval(')) {
      vulnerabilities.push({
        type: 'high',
        category: 'permissions',
        title: 'eval() Usage',
        description: 'Use of eval() function detected',
        recommendation: 'Avoid eval() for security reasons',
        evidence: `File: ${relativePath}`
      });
    }
  }

  return vulnerabilities;
}

function checkForSecrets(content: string): Array<{ type: string; line: number }> {
  const vulnerabilities: Array<{ type: string; line: number }> = [];
  const lines = content.split('\n');
  
  const secretPatterns = [
    /(?:password|passwd|pwd|secret|token|key|api[_-]?key|access[_-]?token)\s*[:=]\s*['"`](.+?)['"`]/gi,
    /bearer\s+(.+?)\s*$/gi,
    /secret['"`]\s*[:=]\s*['"`](.+?)['"`]/gi
  ];

  lines.forEach((line, index) => {
    secretPatterns.forEach(pattern => {
      const match = line.match(pattern);
      if (match) {
        vulnerabilities.push({
          type: match[1] ? 'api_key' : 'password',
          line: index + 1
        });
      }
    });
  });

  return vulnerabilities;
}

function checkForDangerousFunctions(content: string): string[] {
  const dangerousFunctions = [
    'exec', 'spawn', 'child_process', 'fork', 'require',
    'eval', 'Function', 'setTimeout', 'setInterval'
  ];
  
  const found: string[] = [];
  const lines = content.split('\n');
  
  lines.forEach(line => {
    dangerousFunctions.forEach(func => {
      if (line.includes(func + '(')) {
        found.push(func);
      }
    });
  });
  
  return [...new Set(found)];
}

async function getAllFiles(dir: string): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...await getAllFiles(fullPath));
    } else {
      files.push(fullPath);
    }
  }

  return files;
}

async function getDirectorySize(dir: string): Promise<number> {
  const files = await getAllFiles(dir);
  let size = 0;
  
  for (const file of files) {
    const stats = await fs.stat(file);
    size += stats.size;
  }
  
  return size;
}

function detectLanguage(files: string[]): string {
  const extensions = files.map(f => path.extname(f)).filter(ext => ext);
  const languageCount: Record<string, number> = {};
  
  extensions.forEach(ext => {
    languageCount[ext] = (languageCount[ext] || 0) + 1;
  });
  
  const mostCommon = Object.entries(languageCount).sort(([,a], [,b]) => b - a)[0];
  return mostCommon ? mostCommon[0] : 'unknown';
}

function calculateTrustScore(analysis: any, weights: any): number {
  let score = 0;
  
  // Stars weight (normalized, max 1000 stars = full points)
  score += Math.min(analysis.stars / 1000 * weights.stars, weights.stars);
  
  // Tests weight
  if (analysis.hasTests) {
    score += weights.tests;
  }
  
  // CI weight
  if (analysis.hasCI) {
    score += weights.ci;
  }
  
  // Age weight (older repositories get more weight)
  const ageScore = Math.min(analysis.ageInDays / 365 * weights.age, weights.age);
  score += ageScore;
  
  // Add bonus for proper structure
  if (analysis.hasPackageJson && analysis.hasMCPConfig) {
    score += 0.1;
  }
  
  // Bonus for language-specific patterns
  if (analysis.language === '.ts' || analysis.language === '.js') {
    score += 0.05;
  }
  
  return Math.round(score);
}