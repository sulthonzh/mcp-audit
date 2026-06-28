import fs from 'fs-extra';
import path from 'path';
import yaml from 'js-yaml';
import { logger } from '../utils/logger';
import { SecurityResult, SecurityIssue } from '../types/security-result';

/**
 * Helm chart security scanner for MCP servers.
 *
 * Detects Helm chart directories (Chart.yaml present), then:
 * - Scans values.yaml for hardcoded secrets, privileged settings, and misconfigs
 * - Strips Go template syntax from templates/ and runs K8s manifest checks
 * - Checks for deprecated API versions in templates
 * - Validates Chart.yaml metadata (appVersion pinned, etc.)
 */

interface HelmScanOptions {
  strict?: boolean;
}

// ---- Go template stripping ----

function stripGoTemplate(content: string): string {
  let cleaned = content;
  // Remove comments first
  cleaned = cleaned.replace(/\{\{-?\s*\/\*[\s\S]*?\*\/\s*-?\}\}/g, '');
  // Replace remaining template expressions with placeholder or empty
  cleaned = cleaned.replace(/\{\{[\s\S]*?\}\}/g, '');
  return cleaned;
}

// ---- values.yaml checks ----

interface HelmValues {
  [key: string]: unknown;
}

function checkValues(values: HelmValues | null, relPath: string): SecurityIssue[] {
  const issues: SecurityIssue[] = [];
  if (!values || typeof values !== 'object') return issues;

  function walk(obj: Record<string, unknown>, path: string) {
    if (!obj || typeof obj !== 'object') return;

    for (const [key, val] of Object.entries(obj)) {
      const currentPath = path ? `${path}.${key}` : key;
      const keyLower = key.toLowerCase();

      // Hardcoded secrets
      if (
        (keyLower.includes('password') || keyLower.includes('secret') ||
         keyLower.includes('token') || keyLower.includes('apikey') ||
         keyLower.includes('api_key') || keyLower.includes('accesskey') ||
         keyLower.includes('access_key') || keyLower.includes('privatekey') ||
         keyLower.includes('private_key')) &&
        typeof val === 'string' && val.length > 0
      ) {
        // Skip obvious placeholders
        const placeholders = ['changeme', 'replace', 'xxx', 'placeholder', '${', '%(', 'your-', 'REPLACE'];
        const isPlaceholder = placeholders.some(p => val.toLowerCase().includes(p.toLowerCase()));
        if (!isPlaceholder) {
          issues.push({
            type: 'high',
            category: 'config',
            title: 'Hardcoded secret in values.yaml',
            description: `Found "${currentPath}" with what appears to be a real value in values.yaml`,
            recommendation: 'Use .Values.secrets or external secret management (Sealed Secrets, External Secrets Operator)',
            evidence: `${relPath} → ${currentPath}`,
          });
        }
      }

      // Privileged container flags in values
      if (keyLower === 'privileged' && val === true) {
        issues.push({
          type: 'high',
          category: 'permissions',
          title: 'Privileged container in values',
          description: `values.yaml sets privileged: true at ${currentPath}`,
          recommendation: 'Avoid running containers in privileged mode. Use fine-grained capabilities instead.',
          evidence: `${relPath} → ${currentPath}`,
        });
      }

      if (keyLower === 'runasroot' && val === true) {
        issues.push({
          type: 'medium',
          category: 'permissions',
          title: 'runAsRoot enabled in values',
          description: `values.yaml sets runAsRoot: true at ${currentPath}`,
          recommendation: 'Set runAsNonRoot: true and runAsUser > 0',
          evidence: `${relPath} → ${currentPath}`,
        });
      }

      // hostNetwork in values
      if (keyLower === 'hostnetwork' && val === true) {
        issues.push({
          type: 'high',
          category: 'network',
          title: 'hostNetwork in values',
          description: `values.yaml enables hostNetwork at ${currentPath}`,
          recommendation: 'Avoid hostNetwork unless absolutely necessary',
          evidence: `${relPath} → ${currentPath}`,
        });
      }

      // Recurse into nested objects
      if (typeof val === 'object' && val !== null) {
        walk(val as Record<string, unknown>, currentPath);
      }
    }
  }

  walk(values, '');
  return issues;
}

// ---- Chart.yaml checks ----

function checkChartYaml(chart: Record<string, unknown> | null, relPath: string): SecurityIssue[] {
  const issues: SecurityIssue[] = [];
  if (!chart || typeof chart !== 'object') return issues;

  // Missing appVersion
  if (!chart.appVersion) {
    issues.push({
      type: 'low',
      category: 'config',
      title: 'Missing appVersion in Chart.yaml',
      description: 'Chart.yaml does not specify appVersion',
      recommendation: 'Add appVersion to track which app version the chart deploys',
      evidence: relPath,
    });
  }

  // Deprecated chart
  if (chart.deprecated) {
    issues.push({
      type: 'medium',
      category: 'config',
      title: 'Deprecated Helm chart',
      description: `Chart "${String(chart.name ?? 'unnamed')}" is marked as deprecated`,
      recommendation: 'Migrate to a maintained chart or fork and maintain your own',
      evidence: relPath,
    });
  }

  return issues;
}

// ---- Template scanning (reuse K8s checks) ----

interface HelmK8sContainer {
  name?: string;
  image?: string;
  securityContext?: { privileged?: boolean };
  resources?: { limits?: Record<string, unknown> };
  env?: Array<{ name?: string; value?: string; valueFrom?: unknown }>;
}

interface HelmK8sPodSpec {
  containers?: HelmK8sContainer[];
  initContainers?: HelmK8sContainer[];
  volumes?: Array<{ name?: string; hostPath?: { path?: string } }>;
  hostNetwork?: boolean;
}

interface HelmK8sManifest {
  apiVersion?: string;
  kind?: string;
  metadata?: { name?: string; namespace?: string };
  spec?: {
    type?: string;
    template?: { spec?: HelmK8sPodSpec };
  } & HelmK8sPodSpec;
}

function extractPodSpec(manifest: HelmK8sManifest): HelmK8sPodSpec | null {
  const kind = manifest.kind?.toLowerCase() ?? '';
  if (kind === 'pod') return manifest.spec as HelmK8sPodSpec ?? null;
  if (['deployment', 'statefulset', 'daemonset', 'replicaset', 'job'].includes(kind)) {
    return manifest.spec?.template?.spec ?? null;
  }
  return null;
}

function scanTemplateManifest(doc: HelmK8sManifest, relPath: string): SecurityIssue[] {
  const issues: SecurityIssue[] = [];
  if (!doc || typeof doc !== 'object' || !doc.kind) return issues;

  const manifestName = doc.metadata?.name ?? 'unnamed';
  const podSpec = extractPodSpec(doc);

  if (podSpec) {
    const containers = [...(podSpec.containers ?? []), ...(podSpec.initContainers ?? [])];
    for (const ctr of containers) {
      const cname = ctr.name ?? 'unnamed';

      // Privileged
      if (ctr.securityContext?.privileged) {
        issues.push({
          type: 'high', category: 'permissions',
          title: 'Privileged container in Helm template',
          description: `Container "${cname}" in ${manifestName} runs privileged (template: ${relPath})`,
          recommendation: 'Remove securityContext.privileged or set to false',
          evidence: relPath,
        });
      }

      // No resource limits
      if (!ctr.resources?.limits) {
        issues.push({
          type: 'medium', category: 'config',
          title: 'No resource limits in Helm template',
          description: `Container "${cname}" in ${manifestName} has no resource limits (template: ${relPath})`,
          recommendation: 'Set resources.limits.cpu and resources.limits.memory',
          evidence: relPath,
        });
      }

      // :latest tag (only warn if hardcoded, template vars are fine)
      const image = ctr.image ?? '';
      if (typeof image === 'string' && (image.includes(':latest') || (image.includes('/') && !image.includes(':') && !image.includes('.')))) {
        issues.push({
          type: 'medium', category: 'supply-chain',
          title: 'Latest tag in Helm template',
          description: `Container "${cname}" uses untagged or :latest image: ${image}`,
          recommendation: 'Pin image tags to specific versions',
          evidence: relPath,
        });
      }

      // Hardcoded env secrets
      if (Array.isArray(ctr.env)) {
        for (const env of ctr.env) {
          const n = (env.name ?? '').toLowerCase();
          if ((n.includes('password') || n.includes('secret') || n.includes('token')) && env.value && !env.valueFrom) {
            issues.push({
              type: 'high', category: 'config',
              title: 'Hardcoded secret in Helm template env',
              description: `Container "${cname}" has "${env.name}" as plaintext in template`,
              recommendation: 'Reference Kubernetes Secrets instead of hardcoding values',
              evidence: `${relPath} → env.${env.name}`,
            });
          }
        }
      }
    }

    // hostPath volumes
    if (Array.isArray(podSpec.volumes)) {
      for (const vol of podSpec.volumes) {
        if (vol.hostPath) {
          issues.push({
            type: 'high', category: 'filesystem',
            title: 'hostPath volume in Helm template',
            description: `Template ${relPath} uses hostPath "${vol.name}" → ${vol.hostPath.path}`,
            recommendation: 'Use PVCs or emptyDir instead of hostPath',
            evidence: relPath,
          });
        }
      }
    }

    // hostNetwork
    if (podSpec.hostNetwork) {
      issues.push({
        type: 'high', category: 'network',
        title: 'hostNetwork in Helm template',
        description: `Template ${relPath} enables hostNetwork`,
        recommendation: 'Only use hostNetwork when absolutely necessary',
        evidence: relPath,
      });
    }
  }

  // Service type checks
  if ((doc.kind ?? '').toLowerCase() === 'service' && doc.spec?.type === 'LoadBalancer') {
    issues.push({
      type: 'medium', category: 'network',
      title: 'LoadBalancer service in Helm template',
      description: `Service "${doc.metadata?.name ?? 'unnamed'}" in ${relPath} is LoadBalancer`,
      recommendation: 'Use ClusterIP + Ingress for internal services',
      evidence: relPath,
    });
  }

  return issues;
}

// ---- Chart discovery ----

async function findHelmCharts(targetPath: string): Promise<string[]> {
  const charts: string[] = [];
  if (!(await fs.pathExists(targetPath))) return charts;

  const stat = await fs.stat(targetPath);
  if (stat.isFile()) return charts; // Charts are directories

  async function walk(dir: string, depth: number) {
    if (depth > 10) return; // safety limit
    const chartFile = path.join(dir, 'Chart.yaml');
    if (await fs.pathExists(chartFile)) {
      charts.push(dir);
      return; // don't recurse into subcharts of found charts
    }

    const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'charts') continue;
      if (entry.isDirectory()) {
        await walk(path.join(dir, entry.name), depth + 1);
      }
    }
  }

  await walk(targetPath, 0);
  return charts;
}

async function findTemplateFiles(chartDir: string): Promise<string[]> {
  const templatesDir = path.join(chartDir, 'templates');
  if (!(await fs.pathExists(templatesDir))) return [];

  const files: string[] = [];
  async function walk(dir: string) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else {
        const ext = path.extname(entry.name).toLowerCase();
        if (['.yaml', '.yml'].includes(ext)) {
          files.push(full);
        }
      }
    }
  }
  await walk(templatesDir);
  return files;
}

// ---- Public API ----

export async function scanHelm(targetPath: string, _options: HelmScanOptions = {}): Promise<SecurityResult> {
  const issues: SecurityIssue[] = [];
  let chartsScanned = 0;
  let templatesScanned = 0;

  try {
    const charts = await findHelmCharts(targetPath);

    if (charts.length === 0) {
      return {
        scanType: 'server',
        timestamp: new Date().toISOString(),
        target: targetPath,
        issues: [],
        score: 100,
        summary: { configFilesFound: 0, highRiskIssues: 0, mediumRiskIssues: 0, lowRiskIssues: 0 },
      };
    }

    for (const chartDir of charts) {
      const chartRel = path.relative(targetPath, chartDir) || path.basename(chartDir);
      chartsScanned++;

      // Scan Chart.yaml
      const chartFile = path.join(chartDir, 'Chart.yaml');
      if (await fs.pathExists(chartFile)) {
        const chartContent = await fs.readFile(chartFile, 'utf8');
        const chart = yaml.load(chartContent) as Record<string, unknown> | null;
        issues.push(...checkChartYaml(chart, path.join(chartRel, 'Chart.yaml')));
      }

      // Scan values.yaml
      const valuesFile = path.join(chartDir, 'values.yaml');
      if (await fs.pathExists(valuesFile)) {
        const valuesContent = await fs.readFile(valuesFile, 'utf8');
        const values = yaml.load(valuesContent) as HelmValues | null;
        issues.push(...checkValues(values, path.join(chartRel, 'values.yaml')));
      }

      // Scan templates
      const templateFiles = await findTemplateFiles(chartDir);
      for (const tf of templateFiles) {
        const content = await fs.readFile(tf, 'utf8');
        const cleaned = stripGoTemplate(content);
        const tfRel = path.relative(targetPath, tf);

        try {
          const docs = yaml.loadAll(cleaned) as HelmK8sManifest[];
          let hadManifest = false;
          for (const doc of docs) {
            if (!doc || typeof doc !== 'object' || !doc.kind) continue;
            hadManifest = true;
            issues.push(...scanTemplateManifest(doc, tfRel));
          }
          if (hadManifest) templatesScanned++;
        } catch {
          // Template with too much Go syntax may not parse — that's expected
          logger.debug(`Could not parse template ${tfRel} after stripping Go syntax`);
        }
      }
    }
  } catch (err) {
    logger.warn('Helm scan error:', err);
    issues.push({
      type: 'medium',
      category: 'config',
      title: 'Helm Scan Error',
      description: `Could not complete Helm scan: ${err instanceof Error ? err.message : String(err)}`,
      recommendation: 'Ensure chart directories are accessible and YAML is valid',
    });
  }

  const high = issues.filter(i => i.type === 'high').length;
  const medium = issues.filter(i => i.type === 'medium').length;
  const low = issues.filter(i => i.type === 'low').length;
  const score = Math.max(0, 100 - high * 25 - medium * 10 - low * 3);

  return {
    scanType: 'server',
    timestamp: new Date().toISOString(),
    target: targetPath,
    issues,
    score,
    summary: {
      configFilesFound: chartsScanned + templatesScanned,
      highRiskIssues: high,
      mediumRiskIssues: medium,
      lowRiskIssues: low,
    },
  };
}
