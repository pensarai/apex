/**
 * ReportGeneratorAgent
 *
 * Generates comprehensive penetration testing reports from session findings.
 */

import { join } from 'path';
import { readdirSync, readFileSync, writeFileSync, existsSync } from 'fs';
import type {
  ReportGeneratorInput,
  ReportGeneratorResult,
  Finding,
  FindingsCount,
} from './types';

/**
 * Generate a penetration testing report from session findings
 */
export async function generatePentestReport(
  input: ReportGeneratorInput
): Promise<ReportGeneratorResult> {
  const {
    sessionRootPath,
    sessionId,
    target,
    startTime,
    endTime,
    reportTitle = 'Penetration Test Report',
    includeMethodology = true,
  } = input;

  try {
    // Load findings
    const findingsPath = join(sessionRootPath, 'findings');
    const findings = loadFindings(findingsPath);
    const findingsCount = countBySeverity(findings);

    // Generate report content
    const reportContent = buildReportContent({
      title: reportTitle,
      target,
      sessionId,
      startTime,
      endTime,
      findings,
      findingsCount,
      includeMethodology,
    });

    // Write report
    const reportPath = join(sessionRootPath, 'pentest-report.md');
    writeFileSync(reportPath, reportContent);

    return {
      success: true,
      reportPath,
      reportContent,
      findingsCount,
    };
  } catch (error: any) {
    return {
      success: false,
      error: error.message,
      findingsCount: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
    };
  }
}

/**
 * Load findings from the findings directory
 */
function loadFindings(findingsPath: string): Finding[] {
  if (!existsSync(findingsPath)) {
    return [];
  }

  const files = readdirSync(findingsPath).filter((f) => f.endsWith('.json'));

  return files
    .map((f) => {
      try {
        const content = readFileSync(join(findingsPath, f), 'utf-8');
        return JSON.parse(content) as Finding;
      } catch {
        return null;
      }
    })
    .filter((f): f is Finding => f !== null);
}

/**
 * Count findings by severity (including CVSS statistics if available)
 */
function countBySeverity(findings: Finding[]): FindingsCount {
  const baseCounts: FindingsCount = {
    critical: findings.filter((f) => f.severity === 'CRITICAL').length,
    high: findings.filter((f) => f.severity === 'HIGH').length,
    medium: findings.filter((f) => f.severity === 'MEDIUM').length,
    low: findings.filter((f) => f.severity === 'LOW').length,
    total: findings.length,
  };

  // Calculate CVSS stats if any findings have CVSS scores
  const cvssFindings = findings.filter((f) => f.cvss?.score !== undefined);
  if (cvssFindings.length > 0) {
    const scores = cvssFindings.map((f) => f.cvss!.score);
    baseCounts.cvss = {
      averageScore: Math.round((scores.reduce((a, b) => a + b, 0) / scores.length) * 10) / 10,
      maxScore: Math.max(...scores),
      byRange: {
        critical: cvssFindings.filter((f) => f.cvss!.score >= 9.0).length,
        high: cvssFindings.filter((f) => f.cvss!.score >= 7.0 && f.cvss!.score < 9.0).length,
        medium: cvssFindings.filter((f) => f.cvss!.score >= 4.0 && f.cvss!.score < 7.0).length,
        low: cvssFindings.filter((f) => f.cvss!.score >= 0.1 && f.cvss!.score < 4.0).length,
        none: cvssFindings.filter((f) => f.cvss!.score === 0).length,
      },
    };
  }

  return baseCounts;
}

/**
 * Build the markdown report content
 */
function buildReportContent(params: {
  title: string;
  target: string;
  sessionId: string;
  startTime?: string;
  endTime?: string;
  findings: Finding[];
  findingsCount: FindingsCount;
  includeMethodology: boolean;
}): string {
  const {
    title,
    target,
    sessionId,
    startTime,
    endTime,
    findings,
    findingsCount,
    includeMethodology,
  } = params;

  const sections: string[] = [];

  // Title
  sections.push(`# ${title}\n`);

  // Executive Summary
  sections.push(buildExecutiveSummary(target, findingsCount, startTime, endTime));

  // Findings Summary Table
  sections.push(buildFindingsSummaryTable(findingsCount));

  // Methodology (optional)
  if (includeMethodology) {
    sections.push(buildMethodologySection());
  }

  // Detailed Findings
  sections.push(buildDetailedFindings(findings));

  // Recommendations
  sections.push(buildRecommendations(findings));

  // Appendix
  sections.push(buildAppendix(sessionId, findings));

  return sections.join('\n\n---\n\n');
}

/**
 * Build executive summary section
 */
function buildExecutiveSummary(
  target: string,
  findingsCount: FindingsCount,
  startTime?: string,
  endTime?: string
): string {
  const riskLevel = getRiskLevel(findingsCount);

  let summary = `## Executive Summary

**Target:** ${target}
**Overall Risk Level:** ${riskLevel}
**Total Findings:** ${findingsCount.total}

`;

  if (startTime) {
    summary += `**Assessment Period:** ${startTime}`;
    if (endTime) {
      summary += ` to ${endTime}`;
    }
    summary += '\n\n';
  }

  // Risk breakdown
  summary += `### Risk Breakdown

| Severity | Count |
|----------|-------|
| Critical | ${findingsCount.critical} |
| High | ${findingsCount.high} |
| Medium | ${findingsCount.medium} |
| Low | ${findingsCount.low} |

`;

  // Summary paragraph
  if (findingsCount.critical > 0) {
    summary += `**Critical Alert:** This assessment identified ${findingsCount.critical} critical vulnerabilities that require immediate attention. These vulnerabilities could lead to complete system compromise, data breach, or significant business impact.\n\n`;
  } else if (findingsCount.high > 0) {
    summary += `**High Priority:** This assessment identified ${findingsCount.high} high-severity vulnerabilities that should be addressed promptly to prevent potential security incidents.\n\n`;
  } else if (findingsCount.medium > 0) {
    summary += `This assessment identified ${findingsCount.medium} medium-severity vulnerabilities that should be addressed as part of regular security maintenance.\n\n`;
  } else if (findingsCount.low > 0) {
    summary += `This assessment identified ${findingsCount.low} low-severity findings. The overall security posture is acceptable but could be improved.\n\n`;
  } else {
    summary += `No vulnerabilities were identified during this assessment. The target appears to have a strong security posture.\n\n`;
  }

  return summary;
}

/**
 * Get overall risk level based on findings
 */
function getRiskLevel(findingsCount: FindingsCount): string {
  if (findingsCount.critical > 0) return '🔴 CRITICAL';
  if (findingsCount.high > 0) return '🟠 HIGH';
  if (findingsCount.medium > 0) return '🟡 MEDIUM';
  if (findingsCount.low > 0) return '🟢 LOW';
  return '✅ MINIMAL';
}

/**
 * Build findings summary table
 */
function buildFindingsSummaryTable(findingsCount: FindingsCount): string {
  let content = `## Findings Summary

| Metric | Value |
|--------|-------|
| Critical Findings | ${findingsCount.critical} |
| High Findings | ${findingsCount.high} |
| Medium Findings | ${findingsCount.medium} |
| Low Findings | ${findingsCount.low} |
| **Total** | **${findingsCount.total}** |
`;

  // Add CVSS statistics if available
  if (findingsCount.cvss) {
    content += `
### CVSS 4.0 Metrics

| Metric | Value |
|--------|-------|
| Average Score | **${findingsCount.cvss.averageScore}** |
| Highest Score | **${findingsCount.cvss.maxScore}** |
| Critical (9.0-10.0) | ${findingsCount.cvss.byRange.critical} |
| High (7.0-8.9) | ${findingsCount.cvss.byRange.high} |
| Medium (4.0-6.9) | ${findingsCount.cvss.byRange.medium} |
| Low (0.1-3.9) | ${findingsCount.cvss.byRange.low} |
`;
  }

  return content;
}

/**
 * Build methodology section
 */
function buildMethodologySection(): string {
  return `## Methodology

This penetration test was conducted using an automated, AI-driven approach that employs:

### Testing Phases

1. **Attack Surface Discovery**
   - Endpoint enumeration
   - Technology stack identification
   - Authentication mechanism analysis
   - JavaScript endpoint extraction

2. **Vulnerability Testing**
   - SQL/NoSQL Injection testing
   - IDOR and Authorization bypass testing
   - Cross-Site Scripting (XSS) testing
   - Command Injection testing
   - Generic vulnerability testing (SSRF, XXE, SSTI, CSRF, Path Traversal)

3. **Exploitation & Validation**
   - Proof-of-Concept (POC) development
   - Automated POC execution and validation
   - Evidence collection

4. **Reporting**
   - Automated report generation
   - Severity classification
   - Remediation recommendations

### Testing Standards

This assessment follows industry best practices including:
- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)
- NIST Cybersecurity Framework
`;
}

/**
 * Build detailed findings section
 */
function buildDetailedFindings(findings: Finding[]): string {
  if (findings.length === 0) {
    return `## Detailed Findings

No vulnerabilities were identified during this assessment.
`;
  }

  // Sort by CVSS score (if available) or severity
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sortedFindings = [...findings].sort((a, b) => {
    // If both have CVSS scores, sort by score (descending)
    if (a.cvss?.score !== undefined && b.cvss?.score !== undefined) {
      return b.cvss.score - a.cvss.score;
    }
    // If only one has CVSS, prioritize the one with CVSS
    if (a.cvss?.score !== undefined) return -1;
    if (b.cvss?.score !== undefined) return 1;
    // Fall back to severity order
    return severityOrder[a.severity] - severityOrder[b.severity];
  });

  let content = `## Detailed Findings\n\n`;

  for (let i = 0; i < sortedFindings.length; i++) {
    const finding = sortedFindings[i];
    const severityBadge = getSeverityBadge(finding.severity);

    content += `### ${i + 1}. ${finding.title}

**Severity:** ${severityBadge} ${finding.severity}
`;

    // Add CVSS information if available
    if (finding.cvss) {
      const cvssBadge = getCVSSBadge(finding.cvss.score);
      content += `**CVSS 4.0 Score:** ${cvssBadge} **${finding.cvss.score}** (${finding.cvss.severity})
**Vector:** \`${finding.cvss.vectorString}\`
`;
    }

    content += `**Endpoint:** \`${finding.endpoint}\`
**Vulnerability Class:** ${finding.vulnerabilityClass || 'N/A'}

#### Description

${finding.description}

#### Impact

${finding.impact}

#### Evidence

\`\`\`
${finding.evidence}
\`\`\`

#### Proof of Concept

POC Script: \`${finding.pocPath}\`

#### Remediation

${finding.remediation}

`;

    // Add CVSS reasoning if available
    if (finding.cvss?.reasoning) {
      content += `#### CVSS Assessment Reasoning

${finding.cvss.reasoning}

`;
    }

    if (finding.references) {
      content += `#### References

${finding.references}

`;
    }
  }

  return content;
}

/**
 * Get CVSS score badge emoji
 */
function getCVSSBadge(score: number): string {
  if (score >= 9.0) return '🔴';
  if (score >= 7.0) return '🟠';
  if (score >= 4.0) return '🟡';
  if (score > 0) return '🟢';
  return '⚪';
}

/**
 * Get severity badge emoji
 */
function getSeverityBadge(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return '🔴';
    case 'HIGH':
      return '🟠';
    case 'MEDIUM':
      return '🟡';
    case 'LOW':
      return '🟢';
    default:
      return '⚪';
  }
}

/**
 * Build recommendations section
 */
function buildRecommendations(findings: Finding[]): string {
  if (findings.length === 0) {
    return `## Recommendations

No specific remediation actions are required at this time. Continue to:
- Maintain regular security assessments
- Keep systems and dependencies updated
- Monitor for new vulnerabilities
- Implement security best practices
`;
  }

  // Extract unique remediation steps
  const remediations = new Map<string, string[]>();

  for (const finding of findings) {
    const key = finding.severity;
    if (!remediations.has(key)) {
      remediations.set(key, []);
    }
    remediations.get(key)!.push(`- ${finding.title}: ${finding.remediation.split('\n')[0]}`);
  }

  let content = `## Recommendations

### Immediate Actions (Critical & High)

`;

  const critical = remediations.get('CRITICAL') || [];
  const high = remediations.get('HIGH') || [];

  if (critical.length > 0 || high.length > 0) {
    content += [...critical, ...high].join('\n') + '\n\n';
  } else {
    content += 'No critical or high-severity findings require immediate action.\n\n';
  }

  content += `### Short-Term Actions (Medium)

`;

  const medium = remediations.get('MEDIUM') || [];
  if (medium.length > 0) {
    content += medium.join('\n') + '\n\n';
  } else {
    content += 'No medium-severity findings identified.\n\n';
  }

  content += `### Long-Term Improvements (Low)

`;

  const low = remediations.get('LOW') || [];
  if (low.length > 0) {
    content += low.join('\n') + '\n\n';
  } else {
    content += 'No low-severity findings identified.\n\n';
  }

  content += `### General Security Recommendations

1. **Implement Security Headers** - Add CSP, X-Frame-Options, X-XSS-Protection
2. **Regular Security Assessments** - Schedule periodic penetration tests
3. **Security Training** - Train developers on secure coding practices
4. **Patch Management** - Keep all systems and dependencies updated
5. **Monitoring & Logging** - Implement comprehensive security monitoring
`;

  return content;
}

/**
 * Build appendix section
 */
function buildAppendix(sessionId: string, findings: Finding[]): string {
  let content = `## Appendix

### Session Information

- **Session ID:** ${sessionId}
- **Report Generated:** ${new Date().toISOString()}
- **Total Findings:** ${findings.length}

### POC Scripts

The following proof-of-concept scripts were generated during this assessment:

| Finding | POC Path |
|---------|----------|
`;

  for (const finding of findings) {
    content += `| ${finding.title} | \`${finding.pocPath}\` |\n`;
  }

  content += `
### Disclaimer

This report is provided for informational purposes only. The findings represent the security posture at the time of testing. Security is an ongoing process, and new vulnerabilities may emerge after this assessment.

---

*Report generated by Apex Pentest Agent*
`;

  return content;
}
