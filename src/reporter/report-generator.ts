import fs from 'fs-extra';
import path from 'path';
import chalk from 'chalk';
import { SecurityResult, SecurityIssue } from '../types/security-result';
import { logger } from '../utils/logger';

export interface ReportOptions {
  format: 'json' | 'table' | 'summary' | 'sarif';
  output?: string;
}

export async function generateReport(result: SecurityResult, outputPath?: string): Promise<void> {
  logger.info('Generating security report...');

  const options: ReportOptions = {
    format: determineFormat(outputPath),
    output: outputPath
  };

  switch (options.format) {
    case 'json':
      await generateJsonReport(result, options.output);
      break;
    case 'table':
      await generateTableReport(result, options.output);
      break;
    case 'summary':
      await generateSummaryReport(result, options.output);
      break;
    case 'sarif':
      await generateSarifReport(result, options.output);
      break;
  }
}

function determineFormat(outputPath?: string): 'json' | 'table' | 'summary' | 'sarif' {
  if (!outputPath) return 'table'; // Default to table for console output
  
  const ext = path.extname(outputPath).toLowerCase();
  switch (ext) {
    case '.json':
      return 'json';
    case '.sarif':
      return 'sarif';
    case '.txt':
    case '.md':
      return 'summary';
    default:
      return 'table';
  }
}

async function generateJsonReport(result: SecurityResult, outputPath?: string): Promise<void> {
  const report = {
    metadata: {
      scannedAt: result.timestamp,
      scanType: result.scanType,
      target: result.target,
      toolVersion: '1.2.0'
    },
    score: result.score,
    summary: result.summary,
    issues: result.issues.map(issue => ({
      ...issue,
      severity: issue.type
    })),
    recommendations: generateRecommendations(result)
  };

  const output = JSON.stringify(report, null, 2);

  if (outputPath) {
    await fs.writeFile(outputPath, output);
    logger.success(`JSON report saved to: ${outputPath}`);
  } else {
    console.log(output);
  }
}

async function generateTableReport(result: SecurityResult, outputPath?: string): Promise<void> {
  const report = createTableReport(result);
  const output = report;

  if (outputPath) {
    await fs.writeFile(outputPath, output);
    logger.success(`Table report saved to: ${outputPath}`);
  } else {
    console.log(report);
  }
}

async function generateSummaryReport(result: SecurityResult, outputPath?: string): Promise<void> {
  const report = createSummaryReport(result);
  const output = report;

  if (outputPath) {
    await fs.writeFile(outputPath, output);
    logger.success(`Summary report saved to: ${outputPath}`);
  } else {
    console.log(report);
  }
}

function createTableReport(result: SecurityResult): string {
  let output = '';

  // Header
  output += chalk.bold.blue(`\n🔍 MCP Security Report\n`);
  output += chalk.gray(`┌${'─'.repeat(70)}┐\n`);
  output += chalk.gray(`│ Target: ${chalk.white(result.target.padEnd(56))}│\n`);
  output += chalk.gray(`│ Scan Type: ${chalk.white(result.scanType.padEnd(53))}│\n`);
  output += chalk.gray(`│ Timestamp: ${chalk.white(result.timestamp.padEnd(51))}│\n`);
  output += chalk.gray(`└${'─'.repeat(70)}┘\n\n`);

  // Score
  const scoreColor = result.score >= 80 ? chalk.green : 
                     result.score >= 50 ? chalk.yellow : chalk.red;
  output += scoreColor(`🎯 Security Score: ${result.score}/100\n\n`);

  // Summary
  output += chalk.bold('📊 Summary:\n');
  output += `  📁 Config Files Found: ${result.summary.configFilesFound}\n`;
  output += `  🔴 High Risk Issues: ${result.summary.highRiskIssues}\n`;
  output += `  🟡 Medium Risk Issues: ${result.summary.mediumRiskIssues}\n`;
  output += `  🔵 Low Risk Issues: ${result.summary.lowRiskIssues}\n\n`;

  // Issues
  if (result.issues.length > 0) {
    output += chalk.bold('🚨 Security Issues:\n\n');
    
    result.issues.forEach((issue, index) => {
      const severityColor = issue.type === 'high' ? chalk.red : 
                          issue.type === 'medium' ? chalk.yellow : chalk.blue;
      
      output += `${index + 1}. ${severityColor(issue.title)}\n`;
      output += `   Type: ${issue.category}\n`;
      output += `   Description: ${issue.description}\n`;
      output += `   Recommendation: ${issue.recommendation}\n`;
      if (issue.evidence) {
        output += `   Evidence: ${issue.evidence}\n`;
      }
      output += '\n';
    });
  } else {
    output += chalk.green('✅ No security issues detected!\n\n');
  }

  // Recommendations
  output += chalk.bold('💡 Recommendations:\n');
  output += generateRecommendations(result).join('\n');
  output += '\n';

  return output;
}

function createSummaryReport(result: SecurityResult): string {
  let output = '';

  // Header
  output += `# MCP Security Report\n\n`;
  output += `**Target:** ${result.target}\n`;
  output += `**Scan Type:** ${result.scanType}\n`;
  output += `**Date:** ${result.timestamp}\n\n`;

  // Score
  output += `## 🎯 Security Score: ${result.score}/100\n\n`;
  
  const scoreLevel = result.score >= 80 ? 'Good' : 
                     result.score >= 50 ? 'Medium' : 'Poor';
  output += `**Level:** ${scoreLevel}\n\n`;

  // Summary
  output += `## 📊 Summary\n\n`;
  output += `- **Config Files Found:** ${result.summary.configFilesFound}\n`;
  output += `- **High Risk Issues:** ${result.summary.highRiskIssues}\n`;
  output += `- **Medium Risk Issues:** ${result.summary.mediumRiskIssues}\n`;
  output += `- **Low Risk Issues:** ${result.summary.lowRiskIssues}\n\n`;

  // Issues
  if (result.issues.length > 0) {
    output += `## 🚨 Security Issues\n\n`;
    
    const issuesByType = result.issues.reduce((acc, issue) => {
      if (!acc[issue.type]) acc[issue.type] = [];
      acc[issue.type].push(issue);
      return acc;
    }, {} as Record<string, SecurityIssue[]>);

    Object.entries(issuesByType).forEach(([type, issues]) => {
      const severity = type === 'high' ? 'High' : type === 'medium' ? 'Medium' : 'Low';
      output += `### ${severity} Priority Issues\n\n`;
      
      issues.forEach((issue, index) => {
        output += `${index + 1}. **${issue.title}**\n`;
        output += `   - **Type:** ${issue.category}\n`;
        output += `   - **Description:** ${issue.description}\n`;
        output += `   - **Recommendation:** ${issue.recommendation}\n`;
        if (issue.evidence) {
          output += `   - **Evidence:** ${issue.evidence}\n`;
        }
        output += '\n';
      });
    });
  } else {
    output += `## ✅ No Security Issues\n\n`;
    output += `No security issues were detected during the scan.\n\n`;
  }

  // Recommendations
  output += `## 💡 Recommendations\n\n`;
  generateRecommendations(result).forEach(rec => {
    output += `- ${rec}\n`;
  });
  output += '\n';

  // Next Steps
  output += `## 🚀 Next Steps\n\n`;
  output += `1. **Address High Priority Issues:** Fix all high-risk issues immediately\n`;
  output += `2. **Monitor Medium Priority Issues:** Schedule fixes for medium-risk issues\n`;
  output += `3. **Regular Scans:** Run MCP Audit regularly as part of your development workflow\n`;
  output += `4. **CI Integration:** Add MCP Audit to your CI/CD pipeline\n`;
  output += `5. **Stay Updated:** Keep MCP Audit updated to get the latest vulnerability database\n\n`;

  return output;
}

// Import SARIF reporter
import { generateSarifReport } from '../reporters/sarif-reporter';

function generateRecommendations(result: SecurityResult): string[] {
  const recommendations: string[] = [];

  // High-level recommendations based on score
  if (result.score < 50) {
    recommendations.push('⚠️ **Critical:** Security score is very low. Review and fix all issues immediately.');
  } else if (result.score < 80) {
    recommendations.push('⚠️ **Attention:** Security score needs improvement. Address medium and high-risk issues.');
  } else {
    recommendations.push('✅ **Good:** Security score is acceptable. Continue regular monitoring.');
  }

  // Specific recommendations based on issues
  const highRiskIssues = result.issues.filter(issue => issue.type === 'high');
  const configIssues = result.issues.filter(issue => issue.category === 'config');
  const permissionIssues = result.issues.filter(issue => issue.category === 'permissions');

  if (highRiskIssues.length > 0) {
    recommendations.push(`🔴 **Priority:** Address ${highRiskIssues.length} high-risk issues first.`);
  }

  if (configIssues.length > 0) {
    recommendations.push(`📁 **Configuration:** Review MCP configuration settings for security best practices.`);
  }

  if (permissionIssues.length > 0) {
    recommendations.push(`🔐 **Permissions:** Audit file system and network access permissions.`);
  }

  if (result.scanType === 'config' && result.summary.configFilesFound === 0) {
    recommendations.push('🔍 **Discovery:** No MCP configuration files found. Check alternative locations.');
  }

  if (result.score === 100 && result.issues.length === 0) {
    recommendations.push('🎉 **Excellent:** No security issues detected. Keep up good security practices!');
  }

  // General recommendations
  recommendations.push('🔄 **Regular Scans:** Run MCP Audit regularly to maintain security posture.');
  recommendations.push('🔗 **CI Integration:** Integrate MCP Audit into your CI/CD pipeline for automated scanning.');
  recommendations.push('📚 **Documentation:** Keep your MCP server documentation up to date with security considerations.');

  return recommendations;
}