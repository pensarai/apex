/**
 * Analysis Tools
 *
 * Tools that wrap external analysis tools (Semgrep, CodeQL, Joern, TruffleHog)
 * for use by the AnalyzerAgent.
 */

import { tool } from 'ai';
import { z } from 'zod';
import type { WorkspacePaths } from '../workspace';
import type { AnalysisRun, ToolAvailability } from '../types';
import {
  runSemgrep,
  type SemgrepConfig,
  type SemgrepFinding,
} from '../external/semgrep';
import {
  runCodeQL,
  type CodeQLConfig,
  type CodeQLResult,
  CODEQL_LANGUAGES,
} from '../external/codeql';
import {
  runJoern,
  type JoernConfig,
  type JoernFinding,
  JOERN_LANGUAGES,
} from '../external/joern';
import {
  runTrufflehog,
  type TrufflehogConfig,
  type TrufflehogFinding,
} from '../external/trufflehog';
import { appendToResultsJsonl } from '../workspace';

// Define schemas for better type inference
const SemgrepInputSchema = z.object({
  rules: z.array(z.string()).optional().describe('Semgrep rule configs (default: auto, p/security-audit)'),
  exclude: z.array(z.string()).optional().describe('Patterns to exclude from scanning'),
  severity: z.array(z.string()).optional().describe('Severity levels to include (ERROR, WARNING, INFO)'),
});

const CodeQLInputSchema = z.object({
  languages: z.array(z.string()).describe('Languages to analyze (e.g., ["python", "javascript"])'),
  queryPacks: z.array(z.string()).optional().describe('Custom query packs to run'),
});

const JoernInputSchema = z.object({
  languages: z.array(z.string()).describe('Languages to analyze'),
  customQueries: z.array(z.string()).optional().describe('Custom Joern query scripts'),
});

const SecretsInputSchema = z.object({
  includeHistory: z.boolean().optional().default(false).describe('Include git history in scan'),
  verify: z.boolean().optional().default(true).describe('Verify detected secrets'),
});

const DependencyInputSchema = z.object({
  scope: z.enum(['all', 'direct', 'dev']).optional().default('all').describe('Dependency scope to scan'),
});

const EmptyInputSchema = z.object({});

/**
 * Create analysis tools for an agent
 */
export function createAnalysisTools(
  paths: WorkspacePaths,
  toolAvailability: ToolAvailability
) {
  const repoPath = paths.repo;
  const analysisDir = paths.artifacts.analysis;

  /**
   * Run Semgrep analysis
   */
  const run_semgrep = tool({
    description: 'Run Semgrep static analysis on the repository. Semgrep is always available and supports most languages.',
    inputSchema: SemgrepInputSchema,
    execute: async ({ rules, exclude, severity }: z.infer<typeof SemgrepInputSchema>) => {
      if (!toolAvailability.semgrep.available) {
        return {
          success: false,
          error: 'Semgrep is not installed. Install with: pip install semgrep',
          findings: [],
        };
      }

      const config: Partial<SemgrepConfig> = {};
      if (rules) config.rules = rules;
      if (exclude) config.exclude = exclude;
      if (severity) config.severity = severity;

      try {
        const result = await runSemgrep(repoPath, analysisDir, config);

        // Log to JSONL
        await appendToResultsJsonl(paths, {
          type: 'analysis_run',
          tool: 'semgrep',
          timestamp: result.run.timestamp,
          findings_count: result.findings.length,
          success: result.run.success,
        });

        return {
          success: result.run.success,
          error: result.run.error,
          findings: result.findings.slice(0, 100), // Limit for context window
          totalFindings: result.findings.length,
          duration_ms: result.run.duration_ms,
          outputPath: result.run.output,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          findings: [],
        };
      }
    },
  });

  /**
   * Run CodeQL analysis
   */
  const run_codeql = tool({
    description: 'Run CodeQL analysis on the repository. Provides deep semantic analysis with dataflow tracking. Only available for certain languages.',
    inputSchema: CodeQLInputSchema,
    execute: async ({ languages, queryPacks }: z.infer<typeof CodeQLInputSchema>) => {
      if (!toolAvailability.codeql.available) {
        return {
          success: false,
          error: 'CodeQL is not installed. Download from https://github.com/github/codeql-cli-binaries',
          findings: [],
        };
      }

      // Filter to supported languages
      const supportedLangs = languages.filter(
        (lang) => CODEQL_LANGUAGES[lang.toLowerCase()]?.supported
      );

      if (supportedLangs.length === 0) {
        return {
          success: false,
          error: `None of the specified languages are supported by CodeQL. Supported: ${Object.keys(CODEQL_LANGUAGES).join(', ')}`,
          findings: [],
        };
      }

      const config: CodeQLConfig = {
        languages: supportedLangs,
        queryPacks,
      };

      try {
        const result = await runCodeQL(repoPath, analysisDir, config);

        await appendToResultsJsonl(paths, {
          type: 'analysis_run',
          tool: 'codeql',
          timestamp: result.run.timestamp,
          findings_count: result.results.length,
          success: result.run.success,
          languages: supportedLangs,
        });

        return {
          success: result.run.success,
          error: result.run.error,
          findings: result.results.slice(0, 50),
          totalFindings: result.results.length,
          duration_ms: result.run.duration_ms,
          outputPath: result.run.output,
          databasePaths: result.dbPaths,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          findings: [],
        };
      }
    },
  });

  /**
   * Run Joern analysis
   */
  const run_joern = tool({
    description: 'Run Joern code property graph analysis. Best for C/C++ and custom dataflow queries.',
    inputSchema: JoernInputSchema,
    execute: async ({ languages, customQueries }: z.infer<typeof JoernInputSchema>) => {
      if (!toolAvailability.joern.available) {
        return {
          success: false,
          error: 'Joern is not installed. See https://joern.io/docs/installation',
          findings: [],
        };
      }

      // Filter to supported languages
      const supportedLangs = languages.filter(
        (lang) => JOERN_LANGUAGES[lang.toLowerCase()]?.supported
      );

      if (supportedLangs.length === 0) {
        return {
          success: false,
          error: `None of the specified languages are supported by Joern. Supported: ${Object.keys(JOERN_LANGUAGES).join(', ')}`,
          findings: [],
        };
      }

      const config: JoernConfig = {
        languages: supportedLangs,
        customQueries,
      };

      try {
        const result = await runJoern(repoPath, analysisDir, config);

        await appendToResultsJsonl(paths, {
          type: 'analysis_run',
          tool: 'joern',
          timestamp: result.run.timestamp,
          findings_count: result.findings.length,
          success: result.run.success,
        });

        return {
          success: result.run.success,
          error: result.run.error,
          findings: result.findings.slice(0, 50),
          totalFindings: result.findings.length,
          duration_ms: result.run.duration_ms,
          outputPath: result.run.output,
          cpgPath: result.cpgPath,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          findings: [],
        };
      }
    },
  });

  /**
   * Run secrets scan
   */
  const run_secrets_scan = tool({
    description: 'Scan the repository for exposed secrets, API keys, and credentials using TruffleHog.',
    inputSchema: SecretsInputSchema,
    execute: async ({ includeHistory, verify }: z.infer<typeof SecretsInputSchema>) => {
      if (!toolAvailability.trufflehog.available) {
        return {
          success: false,
          error: 'TruffleHog is not installed. Install with: brew install trufflehog',
          findings: [],
        };
      }

      const config: Partial<TrufflehogConfig> = { verify };

      try {
        const result = await runTrufflehog(repoPath, analysisDir, config);

        await appendToResultsJsonl(paths, {
          type: 'analysis_run',
          tool: 'secrets',
          timestamp: result.run.timestamp,
          findings_count: result.findings.length,
          success: result.run.success,
        });

        return {
          success: result.run.success,
          error: result.run.error,
          findings: result.findings.slice(0, 50),
          totalFindings: result.findings.length,
          duration_ms: result.run.duration_ms,
          outputPath: result.run.output,
          verifiedCount: result.findings.filter((f) => f.Verified).length,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          findings: [],
        };
      }
    },
  });

  /**
   * Run dependency vulnerability scan
   */
  const run_dependency_scan = tool({
    description: 'Scan dependencies for known vulnerabilities using Grype or similar tools.',
    inputSchema: DependencyInputSchema,
    execute: async ({ scope }: z.infer<typeof DependencyInputSchema>) => {
      if (!toolAvailability.grype.available) {
        // Fall back to basic package file analysis
        return {
          success: true,
          error: 'Grype not installed - using basic dependency analysis only',
          findings: [],
          note: 'Install Grype for full vulnerability scanning: brew install grype',
        };
      }

      // For now, just report that grype would be run
      // TODO: Implement full grype integration
      return {
        success: true,
        findings: [],
        note: 'Dependency scanning with Grype - implementation pending',
      };
    },
  });

  /**
   * Get available tools status
   */
  const get_tool_status = tool({
    description: 'Get the availability status of all analysis tools',
    inputSchema: EmptyInputSchema,
    execute: async () => {
      return {
        success: true,
        tools: {
          semgrep: toolAvailability.semgrep,
          codeql: toolAvailability.codeql,
          joern: toolAvailability.joern,
          trufflehog: toolAvailability.trufflehog,
          grype: toolAvailability.grype,
        },
        recommendations: getToolRecommendations(toolAvailability),
      };
    },
  });

  return {
    run_semgrep,
    run_codeql,
    run_joern,
    run_secrets_scan,
    run_dependency_scan,
    get_tool_status,
  };
}

/**
 * Get recommendations based on tool availability
 */
function getToolRecommendations(availability: ToolAvailability): string[] {
  const recommendations: string[] = [];

  if (!availability.semgrep.available) {
    recommendations.push('Install Semgrep for basic static analysis: pip install semgrep');
  }

  if (!availability.codeql.available) {
    recommendations.push('Install CodeQL for deep semantic analysis with dataflow tracking');
  }

  if (!availability.trufflehog.available) {
    recommendations.push('Install TruffleHog for secrets detection: brew install trufflehog');
  }

  return recommendations;
}

/**
 * Run all available analysis tools in parallel
 */
export async function runAllAnalysisTools(
  paths: WorkspacePaths,
  toolAvailability: ToolAvailability,
  languages: string[]
): Promise<{
  runs: AnalysisRun[];
  allFindings: Array<{ tool: string; finding: any }>;
}> {
  const runs: AnalysisRun[] = [];
  const allFindings: Array<{ tool: string; finding: any }> = [];

  const repoPath = paths.repo;
  const analysisDir = paths.artifacts.analysis;

  // Run tools in parallel
  const toolPromises: Promise<void>[] = [];

  // Always run Semgrep if available
  if (toolAvailability.semgrep.available) {
    toolPromises.push(
      runSemgrep(repoPath, analysisDir, {})
        .then((result) => {
          runs.push(result.run);
          for (const finding of result.findings) {
            allFindings.push({ tool: 'semgrep', finding });
          }
        })
        .catch((error) => {
          runs.push({
            tool: 'semgrep',
            output: '',
            timestamp: new Date().toISOString(),
            duration_ms: 0,
            success: false,
            error: error.message,
            raw_findings_count: 0,
          });
        })
    );
  }

  // Run CodeQL if available
  if (toolAvailability.codeql.available) {
    const codeqlLangs = languages.filter(
      (l) => CODEQL_LANGUAGES[l.toLowerCase()]?.supported
    );
    if (codeqlLangs.length > 0) {
      toolPromises.push(
        runCodeQL(repoPath, analysisDir, { languages: codeqlLangs })
          .then((result) => {
            runs.push(result.run);
            for (const finding of result.results) {
              allFindings.push({ tool: 'codeql', finding });
            }
          })
          .catch((error) => {
            runs.push({
              tool: 'codeql',
              output: '',
              timestamp: new Date().toISOString(),
              duration_ms: 0,
              success: false,
              error: error.message,
              raw_findings_count: 0,
            });
          })
      );
    }
  }

  // Run TruffleHog if available
  if (toolAvailability.trufflehog.available) {
    toolPromises.push(
      runTrufflehog(repoPath, analysisDir, {})
        .then((result) => {
          runs.push(result.run);
          for (const finding of result.findings) {
            allFindings.push({ tool: 'secrets', finding });
          }
        })
        .catch((error) => {
          runs.push({
            tool: 'secrets',
            output: '',
            timestamp: new Date().toISOString(),
            duration_ms: 0,
            success: false,
            error: error.message,
            raw_findings_count: 0,
          });
        })
    );
  }

  await Promise.all(toolPromises);

  return { runs, allFindings };
}
