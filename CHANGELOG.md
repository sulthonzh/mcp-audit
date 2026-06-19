# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-06-19

### Changed
- Bumped version to 1.2.0 across CLI, JSON reporter, and SARIF reporter.
- Removed unused runtime dependencies: `axios` (imported but never called), `crypto-js` (unused), `inquirer` (unused), `glob` (unused), `ora` (imported but unused in report-generator).
- Removed dead devDependencies: `jest`, `ts-jest`, `@types/jest`, `@types/crypto-js`, `@types/inquirer`, `eslint`, `@typescript-eslint/eslint-plugin`, `@typescript-eslint/parser`.
- Replaced dead Jest/ESLint scripts with native Node.js equivalents (`test:watch` now uses `node --test --watch`).
- Added `prepublishOnly` script to ensure tests pass before publish.
- Added `exports` field for clean ESM/CJS consumption.
- Added `types` field pointing to generated `.d.ts`.

### Fixed
- Version mismatch: `package.json` was 1.1.1 but CLI reported `1.0.0`, SARIF reporter reported `1.0.0`, and JSON reporter embedded `1.0.0`. All now consistently report the package version.

## [1.1.0] - 2026-06-15

### Added
- Docker security scanner (`mcp-audit docker`).
- Kubernetes manifest scanner (`mcp-audit k8s`).
- Helm chart scanner (`mcp-audit helm`).
- SARIF reporter for CI/CD integration.
- Config auto-fixer (`mcp-audit fix`) with dry-run support.
- CI mode with exit codes for pipeline integration.

## [1.0.0] - 2026-06-10

### Added
- Initial release.
- MCP config file scanner (`mcp-audit scan`).
- Remote MCP server auditor (`mcp-audit check <repo>`).
- Trust scoring based on GitHub signals (stars, tests, CI, age).
- JSON, table, and summary report formats.
