import fs from 'fs-extra';
import path from 'path';
import yaml from 'js-yaml';
import { logger } from '../utils/logger';
import { SecurityResult, SecurityIssue } from '../types/security-result';

/**
 * Kubernetes manifest security scanner for MCP servers.
 *
 * Checks Deployments, Pods, Services, and other K8s resources for
 * common security misconfigurations: privileged containers, missing
 * resource limits, exposed secrets, hostPath mounts, etc.
 */

interface K8sScanOptions {
  strict?: boolean;
}

// ---- K8s manifest checks ----

interface K8sManifest {
  apiVersion?: string;
  kind?: string;
  metadata?: { name?: string; namespace?: string };
  spec?: any;
  template?: any; // for Deployment etc.
}

function extractPodSpec(manifest: K8sManifest): any | null {
  const kind = manifest.kind?.toLowerCase() ?? '';
  if (kind === 'pod') return manifest.spec;
  if (['deployment', 'statefulset', 'daemonset', 'replicaset', 'job'].includes(kind)) {
    return manifest.spec?.template?.spec ?? null;
  }
  return null;
}

function checkPodSpec(podSpec: any, relPath: string, manifestName: string): SecurityIssue[] {
  const issues: SecurityIssue[] = [];
  if (!podSpec) return issues;

  const containers = podSpec.containers ?? [];
  const initContainers = podSpec.initContainers ?? [];
  const allContainers = [...containers, ...initContainers];

  for (const ctr of allContainers) {
    const cname = ctr.name ?? 'unnamed-container';

    // Running as root
    if (!ctr.securityContext?.runAsNonRoot) {
      issues.push({
        type: 'high',
        category: 'permissions',
        title: 'Container may run as root',
        description: `Container "${cname}" in ${manifestName} does not set runAsNonRoot: true`,
        recommendation: 'Add securityContext.runAsNonRoot: true and set runAsUser > 0',
        evidence: relPath,
      });
    }

    // Privileged mode
    if (ctr.securityContext?.privileged) {
      issues.push({
        type: 'high',
        category: 'permissions',
        title: 'Privileged container',
        description: `Container "${cname}" in ${manifestName} runs in privileged mode`,
        recommendation: 'Remove securityContext.privileged or set to false. Use capabilities instead.',
        evidence: relPath,
      });
    }

    // No resource limits
    if (!ctr.resources?.limits) {
      issues.push({
        type: 'medium',
        category: 'config',
        title: 'No resource limits set',
        description: `Container "${cname}" in ${manifestName} has no resource limits`,
        recommendation: 'Set resources.limits.cpu and resources.limits.memory to prevent resource exhaustion',
        evidence: relPath,
      });
    }

    // No resource requests
    if (!ctr.resources?.requests) {
      issues.push({
        type: 'low',
        category: 'config',
        title: 'No resource requests set',
        description: `Container "${cname}" in ${manifestName} has no resource requests`,
        recommendation: 'Set resources.requests for predictable scheduling',
        evidence: relPath,
      });
    }

    // HostPath volumes
    if (Array.isArray(ctr.volumeMounts)) {
      for (const vm of ctr.volumeMounts) {
        if (vm.mountPath && vm.mountPath.startsWith('/host')) {
          issues.push({
            type: 'high',
            category: 'filesystem',
            title: 'Suspicious host mount path',
            description: `Container "${cname}" mounts at ${vm.mountPath} — likely a hostPath volume`,
            recommendation: 'Avoid mounting host paths. Use PVCs or emptyDir instead.',
            evidence: relPath,
          });
        }
      }
    }

    // Using :latest tag
    const image = ctr.image ?? '';
    if (image.includes(':latest') || (!image.includes(':') && image.includes('/'))) {
      issues.push({
        type: 'medium',
        category: 'supply-chain',
        title: 'Using latest or untagged image',
        description: `Container "${cname}" uses image "${image}" without a pinned tag`,
        recommendation: 'Pin image tags to specific versions (e.g., nginx:1.25.3) for reproducible builds',
        evidence: relPath,
      });
    }

    // No liveness/readiness probes
    if (!ctr.livenessProbe) {
      issues.push({
        type: 'low',
        category: 'config',
        title: 'No liveness probe',
        description: `Container "${cname}" has no liveness probe`,
        recommendation: 'Add a livenessProbe so K8s can restart unhealthy containers',
        evidence: relPath,
      });
    }
    if (!ctr.readinessProbe) {
      issues.push({
        type: 'low',
        category: 'config',
        title: 'No readiness probe',
        description: `Container "${cname}" has no readiness probe`,
        recommendation: 'Add a readinessProbe to control traffic routing',
        evidence: relPath,
      });
    }

    // Environment variables with potential secrets
    if (Array.isArray(ctr.env)) {
      for (const env of ctr.env) {
        const name = (env.name ?? '').toLowerCase();
        if (name.includes('password') || name.includes('secret') || name.includes('token') || name.includes('key')) {
          if (env.value && !env.valueFrom) {
            issues.push({
              type: 'high',
              category: 'config',
              title: 'Hardcoded secret in env var',
              description: `Container "${cname}" has "${env.name}" set as plaintext in the manifest`,
              recommendation: 'Use Secrets or external secret managers instead of plaintext env vars',
              evidence: `${relPath} → env.${env.name}`,
            });
          }
        }
      }
    }
  }

  // hostPath volumes at pod level
  if (Array.isArray(podSpec.volumes)) {
    for (const vol of podSpec.volumes) {
      if (vol.hostPath) {
        issues.push({
          type: 'high',
          category: 'filesystem',
          title: 'hostPath volume mounted',
          description: `Pod ${manifestName} uses hostPath volume "${vol.name}" → ${vol.hostPath.path}`,
          recommendation: 'Avoid hostPath volumes. They expose the node filesystem to the pod.',
          evidence: relPath,
        });
      }
    }
  }

  // hostNetwork
  if (podSpec.hostNetwork) {
    issues.push({
      type: 'high',
      category: 'network',
      title: 'hostNetwork enabled',
      description: `Pod ${manifestName} uses hostNetwork: true`,
      recommendation: 'Only use hostNetwork when absolutely necessary. It gives the pod access to the node network.',
      evidence: relPath,
    });
  }

  // hostPID / hostIPC
  if (podSpec.hostPID) {
    issues.push({
      type: 'medium',
      category: 'permissions',
      title: 'hostPID enabled',
      description: `Pod ${manifestName} uses hostPID: true`,
      recommendation: 'Avoid hostPID unless needed for debugging.',
      evidence: relPath,
    });
  }
  if (podSpec.hostIPC) {
    issues.push({
      type: 'medium',
      category: 'permissions',
      title: 'hostIPC enabled',
      description: `Pod ${manifestName} uses hostIPC: true`,
      recommendation: 'Avoid hostIPC unless shared memory is required.',
      evidence: relPath,
    });
  }

  return issues;
}

function checkService(manifest: K8sManifest, relPath: string): SecurityIssue[] {
  const issues: SecurityIssue[] = [];
  const spec = manifest.spec;
  if (!spec) return issues;

  const name = manifest.metadata?.name ?? 'unnamed-service';

  // LoadBalancer exposing internally
  if (spec.type === 'LoadBalancer') {
    issues.push({
      type: 'medium',
      category: 'network',
      title: 'Service exposed via LoadBalancer',
      description: `Service "${name}" is a LoadBalancer — it will be externally accessible`,
      recommendation: 'Use ClusterIP + Ingress for internal services. Only use LoadBalancer for public endpoints.',
      evidence: relPath,
    });
  }

  // NodePort
  if (spec.type === 'NodePort') {
    issues.push({
      type: 'low',
      category: 'network',
      title: 'Service uses NodePort',
      description: `Service "${name}" uses NodePort — accessible on all cluster nodes`,
      recommendation: 'Prefer Ingress over NodePort for production workloads.',
      evidence: relPath,
    });
  }

  return issues;
}

function checkManifest(doc: any, relPath: string): SecurityIssue[] {
  const issues: SecurityIssue[] = [];

  if (!doc || typeof doc !== 'object' || !doc.kind) return issues;

  const manifestName = doc.metadata?.name ?? 'unnamed';
  const podSpec = extractPodSpec(doc);
  if (podSpec) {
    issues.push(...checkPodSpec(podSpec, relPath, manifestName));
  }

  if ((doc.kind ?? '').toLowerCase() === 'service') {
    issues.push(...checkService(doc, relPath));
  }

  return issues;
}

// ---- File discovery ----

async function findYamlFiles(targetPath: string): Promise<string[]> {
  const files: string[] = [];
  if (!(await fs.pathExists(targetPath))) return files;

  const stat = await fs.stat(targetPath);
  if (stat.isFile()) {
    const ext = path.extname(targetPath).toLowerCase();
    if (['.yaml', '.yml'].includes(ext)) files.push(targetPath);
    return files;
  }

  async function walk(dir: string) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
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

  await walk(targetPath);
  return files;
}

// ---- Public API ----

export async function scanK8s(targetPath: string, options: K8sScanOptions = {}): Promise<SecurityResult> {
  const issues: SecurityIssue[] = [];
  let filesScanned = 0;

  try {
    const yamlFiles = await findYamlFiles(targetPath);

    for (const fp of yamlFiles) {
      const content = await fs.readFile(fp, 'utf8');
      const rel = path.relative(targetPath, fp);

      // YAML may contain multiple docs separated by ---
      const docs = yaml.loadAll(content) as any[];
      let hadK8sManifest = false;

      for (const doc of docs) {
        if (!doc || typeof doc !== 'object' || !doc.kind) continue;
        hadK8sManifest = true;
        issues.push(...checkManifest(doc, rel));
      }

      if (hadK8sManifest) filesScanned++;
    }
  } catch (err) {
    logger.warn('K8s scan error:', err);
    issues.push({
      type: 'medium',
      category: 'config',
      title: 'K8s Scan Error',
      description: `Could not complete K8s scan: ${err instanceof Error ? err.message : String(err)}`,
      recommendation: 'Ensure the target path is accessible and YAML is valid',
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
      configFilesFound: filesScanned,
      highRiskIssues: high,
      mediumRiskIssues: medium,
      lowRiskIssues: low,
    },
  };
}
