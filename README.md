# MCP Audit 🔍

Security scanner for MCP (Model Context Protocol) servers. The `npm audit` equivalent for your AI agent integrations.

## Why MCP Audit?

Everyone's installing MCP servers like crazy, but there's no security scanner to check if you're about to give a plugin full access to your filesystem, data, and context. MCP Audit gives you visibility into what these servers can do and potential security risks.

## Features

- **Config Scanner**: Analyzes your MCP configuration files for risky permissions
- **Static Code Analysis**: Detects common vulnerabilities in MCP server code
- **Trust Scoring**: Checks GitHub repositories for security signals (tests, CI, stars, known issues)
- **Vulnerability Database**: Community-maintained list of known-vulnerable MCP servers
- **CI Integration**: Add `mcp-audit check` to your deployment pipeline

## Quick Start

```bash
npm install -g mcp-audit

# Scan your current MCP configuration
mcp-audit scan

# Check a specific MCP server
mcp-audit check github.com/user/mcp-server

# Run in CI mode
mcp-audit check --ci
```

## Installation

```bash
npm install mcp-audit
```

## Usage

### Scan Local Configuration
```bash
mcp-audit scan
# Scans claude_desktop_config.json, .cursor/mcp.json, and other MCP config files
```

### Check Remote Server
```bash
mcp-audit check https://github.com/username/mcp-server
# Clones repo, runs security analysis, and generates trust score
```

### CI Integration
```bash
mcp-audit check --ci
# Silent mode suitable for CI pipelines, exits with appropriate codes
```

## Security Reports

MCP Audit generates detailed reports showing:

- 🔍 **Permissions Analysis**: What file system access the server requests
- 🛡️ **Vulnerability Detection**: Prompt injection vectors, hardcoded secrets
- ⭐ **Trust Score**: GitHub repository health and security signals
- 📋 **Configuration Review**: MCP config file security analysis

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
  },
  "allowedFileAccess": ["~/documents", "~/projects"],
  "scanDepth": 2
}
```

## Integrations

### GitHub Action
```yaml
- name: MCP Security Scan
  uses: sulthonzh/mcp-audit-action@v1
```

### Pre-commit Hook
```bash
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

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## Security

If you discover a vulnerability, please email security@your-domain.com. All security vulnerabilities will be promptly addressed.

## License

MIT