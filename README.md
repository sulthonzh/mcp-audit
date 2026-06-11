# MCP Audit 🔍

Security scanner for MCP (Model Context Protocol) servers — and your container/K8s/Helm infrastructure too. Think of it as `npm audit` but for your AI agent integrations and cloud-native deployments.

## Why MCP Audit?

Everyone's installing MCP servers like crazy, but nobody's checking if they're about to give a plugin full access to their filesystem, data, and context. MCP Audit gives you visibility into what these servers can actually do — and flags the risky stuff before it bites you.

It also scans Dockerfiles, Kubernetes manifests, and Helm charts, because your AI tools don't live in a vacuum. They run in containers, on clusters, behind charts. Might as well audit the whole stack.

## What It Scans

| Target | Command | What It Catches |
|--------|---------|-----------------|
| MCP config files | `mcp-audit scan` | Risky permissions, overly broad file access |
| MCP server repos | `mcp-audit check <repo>` | Prompt injection, hardcoded secrets, trust scoring |
| Dockerfiles | `mcp-audit docker <path>` | Root user, exposed secrets, outdated base images |
| Kubernetes manifests | `mcp-audit k8s <path>` | Privileged containers, hostNetwork, runaway resources |
| Helm charts | `mcp-audit helm <path>` | Hardcoded secrets in values.yaml, unsafe defaults |

## Quick Start

```bash
npm install -g mcp-audit

# Scan your MCP config
mcp-audit scan

# Audit a remote MCP server
mcp-audit check github.com/user/mcp-server

# Scan a Dockerfile
mcp-audit docker ./Dockerfile

# Scan K8s manifests
mcp-audit k8s ./manifests

# Scan a Helm chart
mcp-audit helm ./my-chart

# CI mode (exits with code on findings)
mcp-audit check --ci
```

## Usage

### Scan MCP Configuration
Checks `claude_desktop_config.json`, `.cursor/mcp.json`, and other MCP config files for risky permissions.

```bash
mcp-audit scan
mcp-audit scan -o report.json  # save report
```

### Check a Remote Server
Clones the repo, runs static analysis, and generates a trust score based on GitHub signals.

```bash
mcp-audit check https://github.com/username/mcp-server
mcp-audit check https://github.com/username/mcp-server --ci  # CI-friendly
```

### Docker Security
```bash
mcp-audit docker ./Dockerfile
mcp-audit docker ./docker-dir  # scans all Dockerfiles in directory
```

Detects: root user, `ADD` vs `COPY`, hardcoded secrets, `latest` tags, missing `.dockerignore`.

### Kubernetes Security
```bash
mcp-audit k8s ./manifests
mcp-audit k8s ./manifests --strict  # stricter checks
```

Detects: privileged containers, hostNetwork/hostPID, missing resource limits, `alwaysPullPolicy` not set, containers running as root.

### Helm Chart Security
```bash
mcp-audit helm ./my-chart
mcp-audit helm ./my-chart --strict -o report.json
```

Automatically detects Helm charts (looks for `Chart.yaml`). Scans `values.yaml` for hardcoded secrets and privileged flags, strips Go template syntax from `templates/` and runs K8s security checks, and validates `Chart.yaml` for deprecated API versions and missing metadata.

### CI Integration
All scanners support `--ci` for pipeline-friendly output and proper exit codes. Use `--strict` to fail on warnings too.

```yaml
# GitHub Actions example
- name: Security Audit
  run: |
    npx mcp-audit k8s ./k8s --ci --strict
    npx mcp-audit docker . --ci
    npx mcp-audit helm ./charts --ci
```

## Configuration

Create `mcp-audit.config.json` to customize:

```json
{
  "vulnerabilityDatabase": "https://raw.githubusercontent.com/your-org/mcp-vuln-db/main/database.json",
  "trustWeight": {
    "stars": 0.3,
    "tests": 0.3,
    "ci": 0.2,
    "age": 0.2
  }
}
```

## Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: mcp-audit
        name: MCP Security Audit
        entry: mcp-audit check --ci
        language: system
```

## Contributing

PRs welcome. Open an issue first if it's a significant change.

## License

MIT
