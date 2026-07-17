# STATUS.md — mcp-audit

## Exceptional Checklist Audit (2026-07-17)

| # | Criteria | Status | Notes |
|---|----------|--------|-------|
| 1 | README hooks reader in first 3 lines | ✅ | "Security scanner for MCP servers — and your container/K8s/Helm infrastructure too." |
| 2 | Quick start works in <2 minutes | ✅ | `npm install -g @sulthonzh/mcp-audit` → `mcp-audit scan` |
| 3 | All tests GREEN (100% pass rate) | ✅ | 167/167 tests pass (146 original + 21 coverage-gap) |
| 4 | Test coverage ≥ 80% on core logic | ✅ | 96.48% stmts, 83.19% branches, 100% funcs |
| 5 | Zero TypeScript errors (strict mode) | ✅ | `tsc --noEmit` clean |
| 6 | Zero ESLint warnings | ✅ | `eslint src/` clean |
| 7 | No TODO/FIXME in shipped code | ✅ | Verified via grep on src/ |
| 8 | At least 3 real-world examples in docs | ✅ | README has scan, docker, k8s, helm, fix examples |
| 9 | CHANGELOG up to date | ✅ | v1.0.0 → v1.2.0 documented |
| 10 | Modern stack (latest stable versions) | ✅ | Node >=18, TypeScript 5.x, ESM/CJS, c8 coverage |
| 11 | Unique value prop clearly stated | ✅ | "npm audit but for AI agent integrations" — scans MCP servers, Dockerfiles, K8s, Helm |
| 12 | Performance: no obvious O(n²) loops | ✅ | Linear scans, Set lookups O(1) |
| 13 | Security: no hardcoded secrets, input validation | ✅ | Security tool — secrets redacted in output, input validation on config parsing |

## Coverage Breakdown

| File | Stmts | Branch | Funcs | Lines |
|------|-------|--------|-------|-------|
| **All files** | 96.48% | 83.19% | 100% | 96.48% |
| config-loader.ts | 91.46% | 81.48% | 100% | 91.46% |
| sarif-reporter.ts | 100% | 80.64% | 100% | 100% |
| config-fixer.ts | 96.13% | 85.05% | 100% | 96.13% |
| config-scanner.ts | 91.18% | 86.92% | 100% | 91.18% |
| docker-scanner.ts | 95.43% | 84.88% | 100% | 95.43% |
| helm-scanner.ts | 99.77% | 79.81% | 100% | 99.77% |
| k8s-scanner.ts | 98.8% | 75.29% | 100% | 98.8% |
| logger.ts | 100% | 92.5% | 100% | 100% |

## Test Summary

- **Total tests:** 167 (146 previous + 21 coverage-gap)
- **Test suites:** 13
- **Pass rate:** 100%
- **Coverage-gap tests added (2026-07-17):**
  - k8s-scanner: resource requests detection, host mount path via volumeMounts, walk skips hidden/node_modules dirs
  - helm-scanner: hardcoded env secrets in templates, isFile early return, Go template parse error handling, non-existent path
  - docker-scanner: privileged port EXPOSE, ADD from URL, invalid compose YAML, walk skips node_modules/.git, glob matching for Dockerfile.*
  - config-fixer: /* and ~/* arg restriction, inPlace write, fixFilePermissions dry-run vs actual
  - sarif-reporter: generateSarifReport file output + stdout, evidence in results, relative path handling

## Project Info

- **Version:** 1.2.0
- **Dependencies:** @octokit/rest, chalk, commander, fs-extra, js-yaml, simple-git
- **Dev deps:** c8, eslint, tsx, typescript, typescript-eslint
- **CLI commands:** scan, check, docker, k8s, helm, fix
- **Scanners:** config, docker, k8s, helm, server (remote repo)
- **Reporters:** text, JSON, SARIF
- **License:** MIT
