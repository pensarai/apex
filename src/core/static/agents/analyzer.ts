/**
 * AnalyzerAgent
 *
 * Runs static analysis tools (Semgrep, CodeQL, Joern, TruffleHog) in parallel
 * and aggregates results into candidate findings.
 */

import type { AIModel } from '../../ai';
import type { WorkspacePaths } from '../workspace';
import type {
  StaticAnalysisState,
  StaticAgentResult,
  ToolAvailability,
  AnalysisRun,
} from '../types';
import { runAllAnalysisTools } from '../tools/analysis-tools';
import { saveState, appendToResultsJsonl } from '../workspace';
import { createFindingDirect, type CreateFindingParams } from '../tools/finding-tools';
import fs from 'fs/promises';
import path from 'path';

export interface AnalyzerInput {
  paths: WorkspacePaths;
  state: StaticAnalysisState;
  model: AIModel;
  toolAvailability: ToolAvailability;
  abortSignal?: AbortSignal;
  onProgress?: (message: string) => void;
}

export async function runAnalyzerAgent(
  input: AnalyzerInput
): Promise<StaticAgentResult> {
  const { paths, state, toolAvailability, onProgress } = input;
  const startTime = Date.now();
  const artifacts: string[] = [];

  try {
    // Get languages from inventory
    const languages = state.inventory?.languages.map(l => l.name) || [];

    onProgress?.('Running analysis tools in parallel...');

    // Run all tools in parallel
    const { runs, allFindings } = await runAllAnalysisTools(
      paths,
      toolAvailability,
      languages
    );

    // Update state with analysis runs
    state.analysis_runs = runs;

    // Create candidate findings from tool outputs
    let candidatesCreated = 0;

    for (const { tool, finding } of allFindings) {
      try {
        // Convert tool-specific findings to our format
        const candidateData = convertToolFinding(tool, finding);
        if (candidateData) {
          await createFindingDirect(paths, 'analyzer', candidateData);
          candidatesCreated++;
        }
      } catch {
        // Skip findings that can't be converted
      }
    }

    // Save analysis summary
    const summaryPath = path.join(paths.artifacts.analysis, 'analysis_summary.json');
    await fs.writeFile(summaryPath, JSON.stringify({
      runs,
      total_raw_findings: allFindings.length,
      candidates_created: candidatesCreated,
      timestamp: new Date().toISOString(),
    }, null, 2));
    artifacts.push(summaryPath);

    // Update state
    await saveState(paths, state);

    await appendToResultsJsonl(paths, {
      type: 'agent_complete',
      agent: 'analyzer',
      success: true,
      duration_ms: Date.now() - startTime,
      tools_run: runs.length,
      raw_findings: allFindings.length,
      candidates_created: candidatesCreated,
    });

    const successfulTools = runs.filter(r => r.success).map(r => r.tool).join(', ');

    return {
      stage: 'analyzer',
      success: true,
      artifacts,
      summary: `Analysis complete: ${runs.length} tools run (${successfulTools}), ${candidatesCreated} candidates from ${allFindings.length} raw findings`,
      duration_ms: Date.now() - startTime,
    };
  } catch (error: any) {
    await appendToResultsJsonl(paths, {
      type: 'agent_error',
      agent: 'analyzer',
      error: error.message,
      duration_ms: Date.now() - startTime,
    });

    return {
      stage: 'analyzer',
      success: false,
      artifacts,
      summary: `Analysis failed: ${error.message}`,
      error: error.message,
      duration_ms: Date.now() - startTime,
    };
  }
}

/**
 * Convert tool-specific findings to our candidate format
 */
function convertToolFinding(tool: string, finding: any): CreateFindingParams | null {
  switch (tool) {
    case 'semgrep':
      return {
        title: finding.check_id || 'Semgrep Finding',
        description: finding.extra?.message,
        cwe: finding.extra?.metadata?.cwe || [],
        severity: mapSemgrepSeverity(finding.extra?.severity),
        confidence: 0.6,
        file: finding.path,
        startLine: finding.start?.line || 1,
        endLine: finding.end?.line,
        toolEvidence: 'semgrep',
        tags: finding.extra?.metadata?.category ? [finding.extra.metadata.category] : [],
      };

    case 'codeql':
      const loc = finding.locations?.[0]?.physicalLocation;
      return {
        title: finding.ruleId || 'CodeQL Finding',
        description: finding.message,
        cwe: finding.properties?.cwe || [],
        severity: mapCodeQLSeverity(finding.level, finding.properties?.['security-severity']),
        confidence: 0.8,
        file: loc?.artifactLocation?.uri || '',
        startLine: loc?.region?.startLine || 1,
        endLine: loc?.region?.endLine,
        toolEvidence: 'codeql',
        tags: finding.properties?.tags || [],
      };

    case 'secrets':
      const secretLoc = finding.SourceMetadata?.Data?.Filesystem || finding.SourceMetadata?.Data?.Git;
      return {
        title: `Exposed Secret: ${finding.DetectorName || 'Unknown'}`,
        description: `Detected ${finding.Verified ? 'verified' : 'potential'} secret in repository`,
        cwe: ['CWE-798'],
        severity: finding.Verified ? 'critical' : 'high',
        confidence: finding.Verified ? 0.95 : 0.7,
        file: secretLoc?.file || '',
        startLine: secretLoc?.line || 1,
        toolEvidence: 'secrets',
        tags: ['secrets', finding.DetectorName?.toLowerCase()].filter(Boolean),
      };

    default:
      return null;
  }
}

function mapSemgrepSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
  switch (severity?.toUpperCase()) {
    case 'ERROR': return 'high';
    case 'WARNING': return 'medium';
    case 'INFO': return 'low';
    default: return 'medium';
  }
}

function mapCodeQLSeverity(level: string, secSeverity?: string): 'critical' | 'high' | 'medium' | 'low' {
  if (secSeverity) {
    const sev = parseFloat(secSeverity);
    if (sev >= 9.0) return 'critical';
    if (sev >= 7.0) return 'high';
    if (sev >= 4.0) return 'medium';
    return 'low';
  }
  switch (level?.toLowerCase()) {
    case 'error': return 'high';
    case 'warning': return 'medium';
    default: return 'medium';
  }
}
