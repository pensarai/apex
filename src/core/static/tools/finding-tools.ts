/**
 * Finding Tools
 *
 * Tools for creating, managing, and reporting security findings.
 * Used by LocalizeAndProveAgent, TriageAndDedupAgent, and ReportAgent.
 */

import { tool } from 'ai';
import { z } from 'zod';
import { createHash } from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import type { WorkspacePaths } from '../workspace';
import type {
  StaticFinding,
  FindingSeverity,
  FindingStatus,
  RepoRef,
  FindingTrace,
  FindingEvidence,
  StaticAnalysisStage,
} from '../types';
import { appendToResultsJsonl } from '../workspace';

// Define schemas for type inference
const CreateFindingSchema = z.object({
  title: z.string().describe('Short descriptive title for the finding'),
  description: z.string().optional().describe('Detailed description of the vulnerability'),
  cwe: z.array(z.string()).describe('CWE identifiers (e.g., ["CWE-79", "CWE-89"])'),
  severity: z.enum(['critical', 'high', 'medium', 'low']).describe('Severity level'),
  confidence: z.number().min(0).max(1).describe('Confidence score 0.0-1.0'),
  file: z.string().describe('File path where vulnerability exists'),
  startLine: z.number().describe('Starting line number'),
  endLine: z.number().optional().describe('Ending line number'),
  sourcePath: z.string().optional().describe('Source location for dataflow'),
  sourceLine: z.number().optional().describe('Source line number'),
  sourceSymbol: z.string().optional().describe('Source symbol/variable name'),
  sinkPath: z.string().optional().describe('Sink location for dataflow'),
  sinkLine: z.number().optional().describe('Sink line number'),
  sinkSymbol: z.string().optional().describe('Sink symbol/function name'),
  pathSummary: z.string().optional().describe('Summary of the dataflow path'),
  toolEvidence: z.string().optional().describe('Tool name that detected this'),
  evidenceRef: z.string().optional().describe('Reference to evidence file'),
  fixSummary: z.string().optional().describe('How to fix the vulnerability'),
  tags: z.array(z.string()).optional().describe('Tags for categorization'),
});

const UpdateFindingSchema = z.object({
  findingId: z.string().describe('Finding ID to update'),
  status: z.enum(['candidate', 'triaged', 'confirmed', 'rejected']).optional(),
  confidence: z.number().min(0).max(1).optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
  rejectionReason: z.string().optional().describe('Reason for rejection if status is rejected'),
  additionalEvidence: z.string().optional().describe('Additional evidence to add'),
  fixSummary: z.string().optional().describe('Updated fix recommendation'),
  tags: z.array(z.string()).optional().describe('Additional tags to add'),
});

const ListFindingsSchema = z.object({
  status: z.enum(['candidate', 'triaged', 'confirmed', 'rejected']).optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
  minConfidence: z.number().optional().describe('Minimum confidence threshold'),
});

const GetFindingSchema = z.object({
  findingId: z.string().describe('Finding ID to retrieve'),
});

const CheckDuplicateSchema = z.object({
  title: z.string(),
  file: z.string(),
  line: z.number(),
  cwe: z.array(z.string()),
});

const RejectFindingSchema = z.object({
  findingId: z.string(),
  reason: z.string().describe('Explanation of why this is a false positive'),
});

const ConfirmFindingSchema = z.object({
  findingId: z.string(),
  confidence: z.number().min(0).max(1).optional().describe('Updated confidence score'),
});

const EmptySchema = z.object({});

/**
 * Generate a stable finding ID based on content
 */
export function generateFindingId(
  title: string,
  cwe: string[],
  file: string,
  line: number
): string {
  const hash = createHash('sha256');
  hash.update(`${title}:${cwe.join(',')}:${file}:${line}`);
  return `F-${hash.digest('hex').slice(0, 12)}`;
}

// ============================================================================
// Direct helper functions for non-AI agent use
// ============================================================================

export interface CreateFindingParams {
  title: string;
  description?: string;
  cwe: string[];
  severity: FindingSeverity;
  confidence: number;
  file: string;
  startLine: number;
  endLine?: number;
  sourcePath?: string;
  sourceLine?: number;
  sourceSymbol?: string;
  sinkPath?: string;
  sinkLine?: number;
  sinkSymbol?: string;
  pathSummary?: string;
  toolEvidence?: string;
  evidenceRef?: string;
  fixSummary?: string;
  tags?: string[];
}

/**
 * Create a finding directly (for use outside AI agent context)
 */
export async function createFindingDirect(
  paths: WorkspacePaths,
  stage: StaticAnalysisStage,
  params: CreateFindingParams
): Promise<{ success: boolean; findingId: string; findingPath: string; message: string }> {
  const findingsDir = paths.artifacts.findings;
  const findingId = generateFindingId(params.title, params.cwe, params.file, params.startLine);
  const now = new Date().toISOString();

  const repoRefs: RepoRef[] = [
    {
      path: params.file,
      start_line: params.startLine,
      end_line: params.endLine || params.startLine,
    },
  ];

  const trace: FindingTrace = {
    sources: params.sourcePath
      ? [{ path: params.sourcePath, line: params.sourceLine || 0, symbol: params.sourceSymbol || '' }]
      : [],
    sinks: params.sinkPath
      ? [{ path: params.sinkPath, line: params.sinkLine || 0, symbol: params.sinkSymbol || '' }]
      : [{ path: params.file, line: params.startLine, symbol: '' }],
    path_summary: params.pathSummary || `Vulnerability in ${params.file}:${params.startLine}`,
    supporting_evidence: [],
  };

  const evidence: FindingEvidence[] = [];
  if (params.toolEvidence) {
    evidence.push({
      type: 'tool_output',
      tool: params.toolEvidence as any,
      ref: params.evidenceRef || '',
    });
  }

  const finding: StaticFinding = {
    finding_id: findingId,
    title: params.title,
    description: params.description,
    cwe: params.cwe,
    severity: params.severity,
    confidence: params.confidence,
    status: 'candidate',
    repo_refs: repoRefs,
    trace,
    evidence,
    recommendation: {
      fix_summary: params.fixSummary || 'Review and fix the vulnerability',
      safe_patterns: [],
      notes: '',
    },
    metadata: {
      tags: params.tags || [],
      created_by: stage,
      enriched_by: [],
      created_at: now,
      updated_at: now,
    },
  };

  const findingPath = path.join(findingsDir, `${findingId}.json`);
  await fs.writeFile(findingPath, JSON.stringify(finding, null, 2));

  await appendToResultsJsonl(paths, {
    type: 'finding_created',
    finding_id: findingId,
    title: params.title,
    severity: params.severity,
    confidence: params.confidence,
    file: params.file,
    line: params.startLine,
    stage,
    timestamp: now,
  });

  return {
    success: true,
    findingId,
    findingPath,
    message: `Created finding: ${params.title}`,
  };
}

/**
 * List findings directly (for use outside AI agent context)
 */
export async function listFindingsDirect(
  paths: WorkspacePaths,
  filter?: { status?: FindingStatus; severity?: FindingSeverity; minConfidence?: number }
): Promise<{
  success: boolean;
  findings: Array<{
    id: string;
    title: string;
    severity: FindingSeverity;
    confidence: number;
    status: FindingStatus;
    file?: string;
    line?: number;
    cwe: string[];
  }>;
  count: number;
}> {
  const findingsDir = paths.artifacts.findings;

  try {
    const files = await fs.readdir(findingsDir);
    const findings: StaticFinding[] = [];

    for (const file of files) {
      if (!file.endsWith('.json') || file.includes('summary') || file.includes('triage')) continue;

      try {
        const content = await fs.readFile(path.join(findingsDir, file), 'utf-8');
        const finding: StaticFinding = JSON.parse(content);

        if (filter?.status && finding.status !== filter.status) continue;
        if (filter?.severity && finding.severity !== filter.severity) continue;
        if (filter?.minConfidence && finding.confidence < filter.minConfidence) continue;

        findings.push(finding);
      } catch {
        // Skip invalid files
      }
    }

    // Sort by severity then confidence
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    findings.sort((a, b) => {
      const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (sevDiff !== 0) return sevDiff;
      return b.confidence - a.confidence;
    });

    return {
      success: true,
      findings: findings.map((f) => ({
        id: f.finding_id,
        title: f.title,
        severity: f.severity,
        confidence: f.confidence,
        status: f.status,
        file: f.repo_refs[0]?.path,
        line: f.repo_refs[0]?.start_line,
        cwe: f.cwe,
      })),
      count: findings.length,
    };
  } catch (error: any) {
    return {
      success: false,
      findings: [],
      count: 0,
    };
  }
}

/**
 * Get finding by ID directly
 */
export async function getFindingDirect(
  paths: WorkspacePaths,
  findingId: string
): Promise<{ success: boolean; finding?: StaticFinding; error?: string }> {
  const findingPath = path.join(paths.artifacts.findings, `${findingId}.json`);

  try {
    const content = await fs.readFile(findingPath, 'utf-8');
    const finding: StaticFinding = JSON.parse(content);
    return { success: true, finding };
  } catch {
    return { success: false, error: `Finding not found: ${findingId}` };
  }
}

/**
 * Get finding statistics directly
 */
export async function getFindingStatsDirect(
  paths: WorkspacePaths
): Promise<{
  success: boolean;
  stats?: {
    total: number;
    byStatus: Record<FindingStatus, number>;
    bySeverity: Record<FindingSeverity, number>;
    byCwe: Record<string, number>;
  };
}> {
  const findingsDir = paths.artifacts.findings;

  try {
    const files = await fs.readdir(findingsDir);
    const stats = {
      total: 0,
      byStatus: { candidate: 0, triaged: 0, confirmed: 0, rejected: 0 } as Record<FindingStatus, number>,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 } as Record<FindingSeverity, number>,
      byCwe: {} as Record<string, number>,
    };

    for (const file of files) {
      if (!file.endsWith('.json') || file.includes('summary') || file.includes('triage')) continue;

      try {
        const content = await fs.readFile(path.join(findingsDir, file), 'utf-8');
        const finding: StaticFinding = JSON.parse(content);

        stats.total++;
        stats.byStatus[finding.status]++;
        stats.bySeverity[finding.severity]++;

        for (const cwe of finding.cwe) {
          stats.byCwe[cwe] = (stats.byCwe[cwe] || 0) + 1;
        }
      } catch {
        // Skip invalid files
      }
    }

    return { success: true, stats };
  } catch {
    return { success: false };
  }
}

/**
 * Create finding tools for an agent
 */
export function createFindingTools(
  paths: WorkspacePaths,
  stage: StaticAnalysisStage
) {
  const findingsDir = paths.artifacts.findings;

  /**
   * Create a new finding
   */
  const create_finding = tool({
    description: 'Create a new security finding with full details including location, trace, and evidence',
    inputSchema: CreateFindingSchema,
    execute: async ({
      title,
      description,
      cwe,
      severity,
      confidence,
      file,
      startLine,
      endLine,
      sourcePath,
      sourceLine,
      sourceSymbol,
      sinkPath,
      sinkLine,
      sinkSymbol,
      pathSummary,
      toolEvidence,
      evidenceRef,
      fixSummary,
      tags,
    }: z.infer<typeof CreateFindingSchema>) => {
      const findingId = generateFindingId(title, cwe, file, startLine);
      const now = new Date().toISOString();

      // Build repo refs
      const repoRefs: RepoRef[] = [
        {
          path: file,
          start_line: startLine,
          end_line: endLine || startLine,
        },
      ];

      // Build trace
      const trace: FindingTrace = {
        sources: sourcePath
          ? [{ path: sourcePath, line: sourceLine || 0, symbol: sourceSymbol || '' }]
          : [],
        sinks: sinkPath
          ? [{ path: sinkPath, line: sinkLine || 0, symbol: sinkSymbol || '' }]
          : [{ path: file, line: startLine, symbol: '' }],
        path_summary: pathSummary || `Vulnerability in ${file}:${startLine}`,
        supporting_evidence: [],
      };

      // Build evidence
      const evidence: FindingEvidence[] = [];
      if (toolEvidence) {
        evidence.push({
          type: 'tool_output',
          tool: toolEvidence as any,
          ref: evidenceRef || '',
        });
      }

      const finding: StaticFinding = {
        finding_id: findingId,
        title,
        description,
        cwe,
        severity,
        confidence,
        status: 'candidate',
        repo_refs: repoRefs,
        trace,
        evidence,
        recommendation: {
          fix_summary: fixSummary || 'Review and fix the vulnerability',
          safe_patterns: [],
          notes: '',
        },
        metadata: {
          tags: tags || [],
          created_by: stage,
          enriched_by: [],
          created_at: now,
          updated_at: now,
        },
      };

      // Save finding to file
      const findingPath = path.join(findingsDir, `${findingId}.json`);
      await fs.writeFile(findingPath, JSON.stringify(finding, null, 2));

      // Log to JSONL
      await appendToResultsJsonl(paths, {
        type: 'finding_created',
        finding_id: findingId,
        title,
        severity,
        confidence,
        file,
        line: startLine,
        stage,
        timestamp: now,
      });

      return {
        success: true,
        findingId,
        findingPath,
        message: `Created finding: ${title}`,
      };
    },
  });

  /**
   * Update an existing finding
   */
  const update_finding = tool({
    description: 'Update an existing finding with new information',
    inputSchema: UpdateFindingSchema,
    execute: async ({
      findingId,
      status,
      confidence,
      severity,
      rejectionReason,
      additionalEvidence,
      fixSummary,
      tags,
    }: z.infer<typeof UpdateFindingSchema>) => {
      const findingPath = path.join(findingsDir, `${findingId}.json`);

      try {
        const content = await fs.readFile(findingPath, 'utf-8');
        const finding: StaticFinding = JSON.parse(content);

        // Update fields
        if (status) finding.status = status;
        if (confidence !== undefined) finding.confidence = confidence;
        if (severity) finding.severity = severity;
        if (rejectionReason) finding.rejection_reason = rejectionReason;
        if (fixSummary) finding.recommendation.fix_summary = fixSummary;
        if (tags) finding.metadata.tags = [...new Set([...finding.metadata.tags, ...tags])];
        if (!finding.metadata.enriched_by.includes(stage)) {
          finding.metadata.enriched_by.push(stage);
        }
        finding.metadata.updated_at = new Date().toISOString();

        if (additionalEvidence) {
          finding.evidence.push({
            type: 'code_excerpt',
            ref: '',
            content: additionalEvidence,
          });
        }

        await fs.writeFile(findingPath, JSON.stringify(finding, null, 2));

        await appendToResultsJsonl(paths, {
          type: 'finding_updated',
          finding_id: findingId,
          status,
          confidence,
          stage,
          timestamp: new Date().toISOString(),
        });

        return {
          success: true,
          findingId,
          message: `Updated finding ${findingId}`,
        };
      } catch (error: any) {
        return {
          success: false,
          error: `Failed to update finding: ${error.message}`,
        };
      }
    },
  });

  /**
   * List all findings
   */
  const list_findings = tool({
    description: 'List all findings, optionally filtered by status or severity',
    inputSchema: ListFindingsSchema,
    execute: async ({ status, severity, minConfidence }: z.infer<typeof ListFindingsSchema>) => {
      try {
        const files = await fs.readdir(findingsDir);
        const findings: StaticFinding[] = [];

        for (const file of files) {
          if (!file.endsWith('.json')) continue;

          try {
            const content = await fs.readFile(path.join(findingsDir, file), 'utf-8');
            const finding: StaticFinding = JSON.parse(content);

            if (status && finding.status !== status) continue;
            if (severity && finding.severity !== severity) continue;
            if (minConfidence && finding.confidence < minConfidence) continue;

            findings.push(finding);
          } catch {
            // Skip invalid files
          }
        }

        // Sort by severity then confidence
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        findings.sort((a, b) => {
          const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
          if (sevDiff !== 0) return sevDiff;
          return b.confidence - a.confidence;
        });

        return {
          success: true,
          findings: findings.map((f) => ({
            id: f.finding_id,
            title: f.title,
            severity: f.severity,
            confidence: f.confidence,
            status: f.status,
            file: f.repo_refs[0]?.path,
            line: f.repo_refs[0]?.start_line,
            cwe: f.cwe,
          })),
          count: findings.length,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          findings: [],
          count: 0,
        };
      }
    },
  });

  /**
   * Get detailed finding by ID
   */
  const get_finding = tool({
    description: 'Get full details of a specific finding',
    inputSchema: GetFindingSchema,
    execute: async ({ findingId }: z.infer<typeof GetFindingSchema>) => {
      const findingPath = path.join(findingsDir, `${findingId}.json`);

      try {
        const content = await fs.readFile(findingPath, 'utf-8');
        const finding: StaticFinding = JSON.parse(content);
        return { success: true, finding };
      } catch (error: any) {
        return { success: false, error: `Finding not found: ${findingId}` };
      }
    },
  });

  /**
   * Check for duplicate findings
   */
  const check_duplicate = tool({
    description: 'Check if a finding is a duplicate of an existing one',
    inputSchema: CheckDuplicateSchema,
    execute: async ({ title, file, line, cwe }: z.infer<typeof CheckDuplicateSchema>) => {
      try {
        const files = await fs.readdir(findingsDir);

        for (const f of files) {
          if (!f.endsWith('.json')) continue;

          try {
            const content = await fs.readFile(path.join(findingsDir, f), 'utf-8');
            const existing: StaticFinding = JSON.parse(content);

            // Check for duplicates: same file and overlapping lines
            const sameFile = existing.repo_refs.some((ref) => ref.path === file);
            const overlappingLine = existing.repo_refs.some(
              (ref) => line >= ref.start_line && line <= ref.end_line
            );
            const sameCwe = cwe.some((c) => existing.cwe.includes(c));

            if (sameFile && overlappingLine && sameCwe) {
              return {
                isDuplicate: true,
                existingFindingId: existing.finding_id,
                existingTitle: existing.title,
              };
            }
          } catch {
            // Skip invalid files
          }
        }

        return { isDuplicate: false };
      } catch {
        return { isDuplicate: false };
      }
    },
  });

  /**
   * Mark finding as false positive
   */
  const reject_finding = tool({
    description: 'Mark a finding as a false positive with a reason',
    inputSchema: RejectFindingSchema,
    execute: async ({ findingId, reason }: z.infer<typeof RejectFindingSchema>) => {
      const findingPath = path.join(findingsDir, `${findingId}.json`);

      try {
        const content = await fs.readFile(findingPath, 'utf-8');
        const finding: StaticFinding = JSON.parse(content);

        finding.status = 'rejected';
        finding.rejection_reason = reason;
        finding.metadata.updated_at = new Date().toISOString();
        if (!finding.metadata.enriched_by.includes(stage)) {
          finding.metadata.enriched_by.push(stage);
        }

        await fs.writeFile(findingPath, JSON.stringify(finding, null, 2));

        await appendToResultsJsonl(paths, {
          type: 'finding_rejected',
          finding_id: findingId,
          reason,
          stage,
          timestamp: new Date().toISOString(),
        });

        return { success: true, message: `Rejected finding ${findingId}` };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  /**
   * Confirm a finding
   */
  const confirm_finding = tool({
    description: 'Mark a finding as confirmed vulnerability',
    inputSchema: ConfirmFindingSchema,
    execute: async ({ findingId, confidence }: z.infer<typeof ConfirmFindingSchema>) => {
      const findingPath = path.join(findingsDir, `${findingId}.json`);

      try {
        const content = await fs.readFile(findingPath, 'utf-8');
        const finding: StaticFinding = JSON.parse(content);

        finding.status = 'confirmed';
        if (confidence !== undefined) finding.confidence = confidence;
        finding.metadata.updated_at = new Date().toISOString();
        if (!finding.metadata.enriched_by.includes(stage)) {
          finding.metadata.enriched_by.push(stage);
        }

        await fs.writeFile(findingPath, JSON.stringify(finding, null, 2));

        await appendToResultsJsonl(paths, {
          type: 'finding_confirmed',
          finding_id: findingId,
          confidence,
          stage,
          timestamp: new Date().toISOString(),
        });

        return { success: true, message: `Confirmed finding ${findingId}` };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  /**
   * Get finding statistics
   */
  const get_finding_stats = tool({
    description: 'Get statistics about all findings',
    inputSchema: EmptySchema,
    execute: async () => {
      try {
        const files = await fs.readdir(findingsDir);
        const stats = {
          total: 0,
          byStatus: { candidate: 0, triaged: 0, confirmed: 0, rejected: 0 },
          bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
          byCwe: {} as Record<string, number>,
        };

        for (const file of files) {
          if (!file.endsWith('.json')) continue;

          try {
            const content = await fs.readFile(path.join(findingsDir, file), 'utf-8');
            const finding: StaticFinding = JSON.parse(content);

            stats.total++;
            stats.byStatus[finding.status]++;
            stats.bySeverity[finding.severity]++;

            for (const cwe of finding.cwe) {
              stats.byCwe[cwe] = (stats.byCwe[cwe] || 0) + 1;
            }
          } catch {
            // Skip invalid files
          }
        }

        return { success: true, stats };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  return {
    create_finding,
    update_finding,
    list_findings,
    get_finding,
    check_duplicate,
    reject_finding,
    confirm_finding,
    get_finding_stats,
  };
}
