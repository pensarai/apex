/**
 * ReportAgent
 *
 * Generates final reports in SARIF, Markdown, and JSON formats.
 */

import type { AIModel } from '../../ai';
import type { WorkspacePaths } from '../workspace';
import type { StaticAnalysisState, StaticAgentResult, StaticFinding } from '../types';
import { listFindingsDirect, getFindingDirect } from '../tools/finding-tools';
import { saveState, appendToResultsJsonl } from '../workspace';
import fs from 'fs/promises';
import path from 'path';

export interface ReportInput {
  paths: WorkspacePaths;
  state: StaticAnalysisState;
  model: AIModel;
  reportTitle?: string;
}

export async function runReportAgent(input: ReportInput): Promise<StaticAgentResult> {
  const { paths, state, reportTitle = 'Static Analysis Report' } = input;
  const startTime = Date.now();
  const artifacts: string[] = [];

  try {
    const reportsDir = paths.artifacts.reports;

    // Get all confirmed findings
    const confirmedResult = await listFindingsDirect(paths, { status: 'confirmed' });

    // Get all triaged findings
    const triagedResult = await listFindingsDirect(paths, { status: 'triaged' });

    // Load full finding details
    const allFindings: StaticFinding[] = [];
    const findingIds = [
      ...(confirmedResult.findings || []),
      ...(triagedResult.findings || []),
    ];

    for (const f of findingIds) {
      const detail = await getFindingDirect(paths, f.id);
      if (detail.success && detail.finding) {
        allFindings.push(detail.finding);
      }
    }

    // Generate SARIF report
    const sarifPath = path.join(reportsDir, 'report.sarif');
    const sarif = generateSARIF(allFindings, state);
    await fs.writeFile(sarifPath, JSON.stringify(sarif, null, 2));
    artifacts.push(sarifPath);

    // Generate Markdown report
    const mdPath = path.join(reportsDir, 'report.md');
    const markdown = generateMarkdown(allFindings, state, reportTitle);
    await fs.writeFile(mdPath, markdown);
    artifacts.push(mdPath);

    // Generate JSON report
    const jsonPath = path.join(reportsDir, 'report.json');
    const jsonReport = {
      title: reportTitle,
      generated_at: new Date().toISOString(),
      repository: state.repo,
      summary: {
        total_findings: allFindings.length,
        by_severity: countBySeverity(allFindings),
        by_status: countByStatus(allFindings),
      },
      findings: allFindings,
    };
    await fs.writeFile(jsonPath, JSON.stringify(jsonReport, null, 2));
    artifacts.push(jsonPath);

    // Update state with report paths
    state.report = {
      sarif: sarifPath,
      md: mdPath,
      json: jsonPath,
    };
    await saveState(paths, state);

    await appendToResultsJsonl(paths, {
      type: 'agent_complete',
      agent: 'report',
      success: true,
      duration_ms: Date.now() - startTime,
      findings_reported: allFindings.length,
    });

    return {
      stage: 'report',
      success: true,
      artifacts,
      summary: `Reports generated: ${allFindings.length} findings documented in SARIF, Markdown, and JSON`,
      duration_ms: Date.now() - startTime,
    };
  } catch (error: any) {
    await appendToResultsJsonl(paths, {
      type: 'agent_error',
      agent: 'report',
      error: error.message,
      duration_ms: Date.now() - startTime,
    });

    return {
      stage: 'report',
      success: false,
      artifacts,
      summary: `Report generation failed: ${error.message}`,
      error: error.message,
      duration_ms: Date.now() - startTime,
    };
  }
}

/**
 * Generate SARIF format report
 */
function generateSARIF(findings: StaticFinding[], state: StaticAnalysisState): any {
  const rules = new Map<string, any>();

  for (const f of findings) {
    const ruleId = f.cwe[0] || f.finding_id;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description || f.title },
        defaultConfiguration: {
          level: severityToLevel(f.severity),
        },
        properties: {
          tags: f.metadata.tags,
          'security-severity': severityToScore(f.severity),
        },
      });
    }
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Apex Static Analysis',
            version: '1.0.0',
            informationUri: 'https://github.com/pensarai/apex',
            rules: Array.from(rules.values()),
          },
        },
        results: findings.map((f) => ({
          ruleId: f.cwe[0] || f.finding_id,
          level: severityToLevel(f.severity),
          message: { text: f.description || f.title },
          locations: f.repo_refs.map((ref) => ({
            physicalLocation: {
              artifactLocation: { uri: ref.path },
              region: {
                startLine: ref.start_line,
                endLine: ref.end_line,
              },
            },
          })),
          fingerprints: {
            'finding-id': f.finding_id,
          },
        })),
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: new Date().toISOString(),
          },
        ],
      },
    ],
  };
}

/**
 * Generate Markdown report
 */
function generateMarkdown(
  findings: StaticFinding[],
  state: StaticAnalysisState,
  title: string
): string {
  const lines: string[] = [];

  lines.push(`# ${title}`);
  lines.push('');
  lines.push(`**Generated:** ${new Date().toISOString()}`);
  lines.push(`**Repository:** ${state.repo.url || state.repo.root}`);
  lines.push(`**Commit:** ${state.repo.commit}`);
  lines.push('');

  // Executive Summary
  lines.push('## Executive Summary');
  lines.push('');
  const bySev = countBySeverity(findings);
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Critical | ${bySev.critical} |`);
  lines.push(`| High | ${bySev.high} |`);
  lines.push(`| Medium | ${bySev.medium} |`);
  lines.push(`| Low | ${bySev.low} |`);
  lines.push(`| **Total** | **${findings.length}** |`);
  lines.push('');

  // Findings by severity
  const severityOrder = ['critical', 'high', 'medium', 'low'] as const;

  for (const sev of severityOrder) {
    const sevFindings = findings.filter((f) => f.severity === sev);
    if (sevFindings.length === 0) continue;

    lines.push(`## ${sev.charAt(0).toUpperCase() + sev.slice(1)} Severity Findings`);
    lines.push('');

    for (const f of sevFindings) {
      lines.push(`### ${f.title}`);
      lines.push('');
      lines.push(`**ID:** ${f.finding_id}`);
      lines.push(`**CWE:** ${f.cwe.join(', ') || 'N/A'}`);
      lines.push(`**Confidence:** ${Math.round(f.confidence * 100)}%`);
      lines.push('');

      if (f.description) {
        lines.push(f.description);
        lines.push('');
      }

      lines.push('**Location:**');
      for (const ref of f.repo_refs) {
        lines.push(`- \`${ref.path}:${ref.start_line}\``);
      }
      lines.push('');

      if (f.trace.path_summary) {
        lines.push('**Dataflow:**');
        lines.push(f.trace.path_summary);
        lines.push('');
      }

      lines.push('**Recommendation:**');
      lines.push(f.recommendation.fix_summary);
      lines.push('');
      lines.push('---');
      lines.push('');
    }
  }

  return lines.join('\n');
}

function severityToLevel(severity: string): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    default:
      return 'note';
  }
}

function severityToScore(severity: string): string {
  switch (severity) {
    case 'critical':
      return '9.0';
    case 'high':
      return '7.0';
    case 'medium':
      return '4.0';
    default:
      return '2.0';
  }
}

function countBySeverity(findings: StaticFinding[]): Record<string, number> {
  return {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
  };
}

function countByStatus(findings: StaticFinding[]): Record<string, number> {
  return {
    confirmed: findings.filter((f) => f.status === 'confirmed').length,
    triaged: findings.filter((f) => f.status === 'triaged').length,
    candidate: findings.filter((f) => f.status === 'candidate').length,
    rejected: findings.filter((f) => f.status === 'rejected').length,
  };
}
