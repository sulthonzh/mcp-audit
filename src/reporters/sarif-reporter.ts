/**
 * SARIF (Static Analysis Results Interchange Format) reporter for mcp-audit.
 *
 * Produces SARIF v2.1.0 output compatible with GitHub Code Scanning,
 * Azure DevOps, and other SARIF-consuming tools.
 *
 * @see https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import fs from 'fs-extra';
import { SecurityResult, SecurityIssue } from '../types/security-result';
import { logger } from '../utils/logger';

const TOOL_NAME = 'mcp-audit';
const TOOL_VERSION = '1.2.0';
const TOOL_INFO_URI = 'https://github.com/sulthonzh/mcp-audit';

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  properties: {
    tags: string[];
    'precision': string;
  };
  defaultConfiguration: {
    level: 'error' | 'warning' | 'note';
  };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number; startColumn: number };
    };
  }>;
  properties?: {
    category: string;
    recommendation: string;
    evidence?: string;
  };
}

function severityToLevel(type: string): 'error' | 'warning' | 'note' {
  switch (type) {
    case 'high': return 'error';
    case 'medium': return 'warning';
    default: return 'note';
  }
}

function categoryToRuleId(category: string, title: string): string {
  const prefix = `MA${category.charAt(0).toUpperCase()}`;
  // Create a short hash from the title for uniqueness
  const hash = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .split('-')
    .slice(0, 4)
    .join('-');
  return `${prefix}/${hash}`;
}

function buildRules(issues: SecurityIssue[]): { rules: SarifRule[]; ruleMap: Map<string, number> } {
  const rules: SarifRule[] = [];
  const ruleMap = new Map<string, number>();
  const seen = new Set<string>();

  for (const issue of issues) {
    const ruleId = categoryToRuleId(issue.category, issue.title);
    if (seen.has(ruleId)) continue;
    seen.add(ruleId);

    ruleMap.set(`${issue.category}:${issue.title}`, rules.length);
    rules.push({
      id: ruleId,
      name: issue.title.replace(/[^a-zA-Z0-9]/g, ''),
      shortDescription: { text: issue.title },
      fullDescription: { text: issue.description },
      helpUri: `${TOOL_INFO_URI}#rules`,
      properties: {
        tags: ['security', issue.category],
        precision: 'medium',
      },
      defaultConfiguration: {
        level: severityToLevel(issue.type),
      },
    });
  }

  return { rules, ruleMap };
}

function buildResults(
  issues: SecurityIssue[],
  ruleMap: Map<string, number>,
  targetUri: string,
): SarifResult[] {
  return issues.map((issue) => {
    const key = `${issue.category}:${issue.title}`;
    const ruleIndex = ruleMap.get(key) ?? 0;
    const ruleId = categoryToRuleId(issue.category, issue.title);

    const result: SarifResult = {
      ruleId,
      ruleIndex,
      level: severityToLevel(issue.type),
      message: { text: issue.description },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: targetUri },
            region: { startLine: 1, startColumn: 1 },
          },
        },
      ],
      properties: {
        category: issue.category,
        recommendation: issue.recommendation,
      },
    };

    if (issue.evidence) {
      result.properties!.evidence = issue.evidence;
    }

    return result;
  });
}

/**
 * Generate a SARIF v2.1.0 report from a SecurityResult.
 */
export function generateSarifOutput(result: SecurityResult): object {
  const targetUri = result.target.startsWith('/')
    ? `file://${result.target}`
    : result.target;

  const { rules, ruleMap } = buildRules(result.issues);
  const results = buildResults(result.issues, ruleMap, targetUri);

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: TOOL_INFO_URI,
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: result.timestamp,
            endTimeUtc: new Date().toISOString(),
          },
        ],
        properties: {
          scanType: result.scanType,
          securityScore: result.score,
          summary: result.summary,
        },
      },
    ],
  };
}

/**
 * Write SARIF report to file or stdout.
 */
export async function generateSarifReport(
  result: SecurityResult,
  outputPath?: string,
): Promise<void> {
  const sarif = generateSarifOutput(result);

  if (outputPath) {
    await fs.writeFile(outputPath, JSON.stringify(sarif, null, 2));
    logger.success(`SARIF report saved to: ${outputPath}`);
  } else {
    console.log(JSON.stringify(sarif, null, 2));
  }
}
