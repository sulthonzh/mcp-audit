import fs from 'fs-extra';
import path from 'path';
import yaml from 'js-yaml';
import { logger } from '../utils/logger';
import { SecurityResult, SecurityIssue } from '../types/security-result';

/**
 * Docker/Container security scanner for MCP servers.
 *
 * Checks Dockerfiles, docker-compose files, and container configs
 * for common security misconfigurations.
 */

interface DockerScanOptions {
  strict?: boolean; // Treat warnings as errors
}

// ---- Public API ----

export async function scanDocker(targetPath: string, _options: DockerScanOptions = {}): Promise<SecurityResult> {
  const issues: SecurityIssue[] = [];
  let filesScanned = 0;

  try {
    // Scan Dockerfiles
    const dockerfiles = await findFiles(targetPath, ['Dockerfile', 'Dockerfile.*']);
    for (const df of dockerfiles) {
      filesScanned++;
      const content = await fs.readFile(df, 'utf8');
      const rel = path.relative(targetPath, df);
      issues.push(...checkDockerfile(content, rel));
    }

    // Scan docker-compose files
    const composeFiles = await findFiles(targetPath, [
      'docker-compose.yml', 'docker-compose.yaml',
      'compose.yml', 'compose.yaml',
    ]);
    for (const cf of composeFiles) {
      filesScanned++;
      const content = await fs.readFile(cf, 'utf8');
      const rel = path.relative(targetPath, cf);
      issues.push(...checkComposeFile(content, rel));
    }

    // Scan .env files for leaked secrets
    const envFiles = await findFiles(targetPath, ['.env', '.env.*']);
    for (const ef of envFiles) {
      filesScanned++;
      const content = await fs.readFile(ef, 'utf8');
      const rel = path.relative(targetPath, ef);
      issues.push(...checkEnvFile(content, rel));
    }
  } catch (err) {
    logger.warn('Docker scan error:', err);
    issues.push({
      type: 'medium',
      category: 'config',
      title: 'Docker Scan Error',
      description: `Could not complete container scan: ${err instanceof Error ? err.message : String(err)}`,
      recommendation: 'Ensure the target path is accessible',
    });
  }

  const high = issues.filter(i => i.type === 'high').length;
  const medium = issues.filter(i => i.type === 'medium').length;
  const low = issues.filter(i => i.type === 'low').length;

  // Score: start at 100, deduct per issue
  const score = Math.max(0, 100 - high * 25 - medium * 10 - low * 3);

  return {
    scanType: 'server',
    timestamp: new Date().toISOString(),
    target: targetPath,
    issues,
    score,
    summary: {
      configFilesFound: filesScanned,
      highRiskIssues: high,
      mediumRiskIssues: medium,
      lowRiskIssues: low,
    },
    metadata: { scanKind: 'docker' },
  };
}

// ---- Dockerfile Checks ----

function checkDockerfile(content: string, filePath: string): SecurityIssue[] {
  const issues: SecurityIssue[] = [];
  const lines = content.split('\n');
  const lineNo = (idx: number) => idx + 1;

  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    const upper = trimmed.toUpperCase();

    // Running as root
    if (/^USER\s+ROOT/i.test(upper)) {
      issues.push({
        type: 'high',
        category: 'permissions',
        title: 'Container Runs as Root',
        description: `Line ${lineNo(idx)}: USER root — containers should run as non-root`,
        recommendation: 'Add a non-root user: RUN adduser --disabled-password appuser && USER appuser',
        evidence: `${filePath}:${lineNo(idx)}`,
      });
    }

    // --no-auth or --insecure flags in RUN commands
    if (/^RUN\b/i.test(trimmed)) {
      if (/--no-verify-ssl|--insecure|--no-check-certificate/i.test(trimmed)) {
        issues.push({
          type: 'high',
          category: 'transport',
          title: 'Insecure Download in Build',
          description: `Line ${lineNo(idx)}: skips TLS/SSL verification during build`,
          recommendation: 'Remove --insecure/--no-verify-ssl flags and use trusted registries',
          evidence: `${filePath}:${lineNo(idx)}`,
        });
      }

      // curl | sh patterns
      if (/curl.*\|\s*(sh|bash|sudo)/i.test(trimmed)) {
        issues.push({
          type: 'high',
          category: 'supply-chain',
          title: 'Pipe to Shell in Build',
          description: `Line ${lineNo(idx)}: downloading and executing code in one step`,
          recommendation: 'Download first, verify checksum/signature, then execute',
          evidence: `${filePath}:${lineNo(idx)}`,
        });
      }

      // apt-get without --no-install-recommends
      if (/apt-get install(?!.*--no-install-recommends)/i.test(trimmed)) {
        issues.push({
          type: 'low',
          category: 'config',
          title: 'Bloated apt-get Install',
          description: `Line ${lineNo(idx)}: apt-get install without --no-install-recommends bloats image`,
          recommendation: 'Use: apt-get install --no-install-recommends',
          evidence: `${filePath}:${lineNo(idx)}`,
        });
      }
    }

    // EXPOSE privileged ports
    const exposeMatch = upper.match(/^EXPOSE\s+(\d+)/);
    if (exposeMatch && parseInt(exposeMatch[1]) < 1024) {
      issues.push({
        type: 'low',
        category: 'network',
        title: 'Privileged Port Exposed',
        description: `Line ${lineNo(idx)}: EXPOSE ${exposeMatch[1]} — privileged port (<1024)`,
        recommendation: 'Use high ports (>1024) and map to privileged ports at runtime if needed',
        evidence: `${filePath}:${lineNo(idx)}`,
      });
    }

    // ADD from URL (use COPY instead)
    if (/^ADD\s+https?:\/\//i.test(trimmed)) {
      issues.push({
        type: 'medium',
        category: 'supply-chain',
        title: 'ADD from Remote URL',
        description: `Line ${lineNo(idx)}: ADD from URL is not reproducible and can't be cached`,
        recommendation: 'Use COPY with files checked into the repo, or download + verify in a RUN step',
        evidence: `${filePath}:${lineNo(idx)}`,
      });
    }

    // :latest tag
    if (/^FROM\s+.*:latest/i.test(trimmed)) {
      issues.push({
        type: 'medium',
        category: 'supply-chain',
        title: 'Floating Image Tag (:latest)',
        description: `Line ${lineNo(idx)}: using :latest tag — non-reproducible builds`,
        recommendation: 'Pin to a specific version, e.g. node:20.11-alpine',
        evidence: `${filePath}:${lineNo(idx)}`,
      });
    }

    // Hardcoded secrets
    if (/(?:password|secret|token|api_key|apikey)\s*=\s*\S+/i.test(trimmed) && !trimmed.startsWith('#')) {
      issues.push({
        type: 'high',
        category: 'config',
        title: 'Hardcoded Secret in Dockerfile',
        description: `Line ${lineNo(idx)}: possible secret in plaintext`,
        recommendation: 'Use build args, Docker secrets, or environment variables',
        evidence: `${filePath}:${lineNo(idx)}`,
      });
    }
  });

  // Check if no USER directive at all (likely running as root by default)
  const hasUserDirective = lines.some(l => /^USER\s+/i.test(l.trim()));
  if (!hasUserDirective && lines.some(l => /^FROM\s+/i.test(l.trim()))) {
    issues.push({
      type: 'medium',
      category: 'permissions',
      title: 'No USER Directive',
      description: 'No USER instruction found — container will run as root by default',
      recommendation: 'Add USER directive with a non-root user',
      evidence: filePath,
    });
  }

  // Check for HEALTHCHECK
  const hasHealthcheck = lines.some(l => /^HEALTHCHECK\b/i.test(l.trim()));
  if (!hasHealthcheck && lines.some(l => /^FROM\s+/i.test(l.trim()))) {
    issues.push({
      type: 'low',
      category: 'config',
      title: 'No HEALTHCHECK Defined',
      description: 'No HEALTHCHECK instruction — orchestrators cannot monitor container health',
      recommendation: 'Add HEALTHCHECK for production containers',
      evidence: filePath,
    });
  }

  return issues;
}

// ---- Docker Compose Checks ----

interface ComposeService {
  privileged?: boolean;
  network_mode?: string;
  volumes?: Array<string | { source?: string }>;
  read_only?: boolean;
  image?: string;
}

interface ComposeDoc {
  services?: Record<string, ComposeService>;
}

function checkComposeFile(content: string, filePath: string): SecurityIssue[] {
  const issues: SecurityIssue[] = [];

  let doc: ComposeDoc | null;
  try {
    doc = yaml.load(content) as ComposeDoc | null;
  } catch {
    issues.push({
      type: 'low',
      category: 'config',
      title: 'Invalid YAML',
      description: `Could not parse ${filePath}`,
      recommendation: 'Fix YAML syntax errors',
    });
    return issues;
  }

  const services = doc?.services || {};
  for (const [name, svc] of Object.entries(services)) {
    const s = svc;

    // privileged: true
    if (s.privileged === true) {
      issues.push({
        type: 'high',
        category: 'permissions',
        title: 'Privileged Container',
        description: `Service "${name}" runs in privileged mode — full host access`,
        recommendation: 'Remove privileged: true and use specific capabilities instead',
        evidence: `${filePath} → services.${name}.privileged`,
      });
    }

    // host network
    if (s.network_mode === 'host') {
      issues.push({
        type: 'high',
        category: 'network',
        title: 'Host Network Mode',
        description: `Service "${name}" uses host networking — bypasses container isolation`,
        recommendation: 'Use bridge networking with port mapping',
        evidence: `${filePath} → services.${name}.network_mode`,
      });
    }

    // bind mount to sensitive host paths
    const volumes: Array<string | { source?: string }> = s.volumes || [];
    volumes.forEach(v => {
      const bindPath = typeof v === 'string' ? v.split(':')[0] : v?.source;
      if (typeof bindPath === 'string') {
        const sensitivePaths = ['/var/run/docker.sock', '/', '/etc', '/root', '/home', '/var'];
        const risky = sensitivePaths.find(p => bindPath === p || bindPath === '/var/run/docker.sock');
        if (risky) {
          issues.push({
            type: 'high',
            category: 'filesystem',
            title: 'Sensitive Host Mount',
            description: `Service "${name}" mounts ${bindPath} from host`,
            recommendation: 'Avoid mounting sensitive host paths into containers',
            evidence: `${filePath} → services.${name}.volumes: ${v}`,
          });
        }
      }
    });

    // Docker socket mount
    const hasSocket = volumes.some((v) => {
      const src = typeof v === 'string' ? v.split(':')[0] : v?.source;
      return src === '/var/run/docker.sock';
    });
    if (hasSocket) {
      issues.push({
        type: 'high',
        category: 'permissions',
        title: 'Docker Socket Mounted',
        description: `Service "${name}" has access to Docker socket — equivalent to root on host`,
        recommendation: 'Avoid mounting docker.sock; use TCP with TLS or Docker API proxy',
        evidence: `${filePath} → services.${name}`,
      });
    }

    // no read_only / no resource limits
    if (s.read_only !== true) {
      issues.push({
        type: 'low',
        category: 'config',
        title: 'Writable Container Filesystem',
        description: `Service "${name}" has writable root filesystem`,
        recommendation: 'Add read_only: true and use tmpfs for writable paths',
        evidence: `${filePath} → services.${name}`,
      });
    }

    // Floating image tag
    if (typeof s.image === 'string' && (s.image.endsWith(':latest') || !s.image.includes(':'))) {
      issues.push({
        type: 'medium',
        category: 'supply-chain',
        title: 'Floating Image Tag in Compose',
        description: `Service "${name}" uses ${s.image} — non-reproducible`,
        recommendation: 'Pin image versions: image: node:20.11-alpine',
        evidence: `${filePath} → services.${name}.image`,
      });
    }
  }

  return issues;
}

// ---- .env File Checks ----

function checkEnvFile(content: string, filePath: string): SecurityIssue[] {
  const issues: SecurityIssue[] = [];
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;

    const match = trimmed.match(/^(\w+)\s*=\s*(.+)$/);
    if (!match) return;

    const [, key, value] = match;
    const cleanVal = value.replace(/^["']|["']$/g, '');

    // Detect secrets in .env
    const secretKeys = /(?:password|secret|token|api[_-]?key|private[_-]?key|auth|credential)/i;
    if (secretKeys.test(key) && cleanVal.length > 0 && cleanVal !== 'CHANGEME' && cleanVal !== 'xxx') {
      issues.push({
        type: 'high',
        category: 'config',
        title: 'Secret in .env File',
        description: `${key} appears to contain a secret value`,
        recommendation: 'Use Docker secrets, vault, or CI secret management instead of .env files',
        evidence: `${filePath}:${idx + 1} (${key}=***)`,
      });
    }
  });

  // Warn about .env not in .dockerignore
  issues.push({
    type: 'medium',
    category: 'config',
    title: '.env File Present',
    description: `${filePath} — ensure .env is in .dockerignore to avoid leaking secrets into images`,
    recommendation: 'Add .env to .dockerignore and use runtime environment variables or secrets',
    evidence: filePath,
  });

  return issues;
}

// ---- Helpers ----

async function findFiles(root: string, patterns: string[]): Promise<string[]> {
  const found: string[] = [];

  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > 5) return; // don't go too deep
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (entry.name.startsWith('.') && entry.name !== '.env') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        // skip node_modules and common junk dirs
        if (['node_modules', '.git', 'dist', 'build', '__pycache__'].includes(entry.name)) continue;
        await walk(full, depth + 1);
      } else {
        for (const p of patterns) {
          if (p.includes('*')) {
            // simple glob: Dockerfile.*
            const prefix = p.replace(/\.\*.*/, '');
            if (entry.name.startsWith(prefix) || matchGlob(entry.name, p)) {
              found.push(full);
            }
          } else if (entry.name === p) {
            found.push(full);
          }
        }
      }
    }
  }

  await walk(root, 0);
  return found;
}

function matchGlob(name: string, pattern: string): boolean {
  const re = new RegExp('^' + pattern.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$');
  return re.test(name);
}
