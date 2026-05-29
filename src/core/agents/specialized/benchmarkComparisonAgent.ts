import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";
import { hasToolCall, stepCountIs } from "ai";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { AIAuthConfig, AIModel, OpenAIReasoningEffort } from "../../ai";
import type { SessionInfo } from "../../session";
import { OffensiveSecurityAgent } from "../offSecAgent";
import type { ComparisonResult } from "./benchmark";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BenchmarkComparisonAgentInput {
  /** Path to the benchmark repo containing expected results */
  repoPath: string;

  /** AI model to drive the comparison */
  model: AIModel;

  /** Session that provides the findings to compare */
  session: SessionInfo;

  /** Optional per-provider API key overrides */
  authConfig?: AIAuthConfig;

  /** Optional callback after each agent step */
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;

  /** AbortSignal to cancel mid-run */
  abortSignal?: AbortSignal;

  /** Enable extended thinking (reasoning) for supported models. */
  enableThinking?: boolean;

  /** OpenAI reasoning effort for GPT/o-series reasoning models. */
  openAIReasoningEffort?: OpenAIReasoningEffort | null;
}

/** The typed result returned by `BenchmarkComparisonAgent.consume()`. */
export interface BenchmarkComparisonResult {
  /** The full comparison result with metrics */
  comparison: ComparisonResult | null;
  /** Path to the comparison results JSON */
  resultsPath: string;
}

// ---------------------------------------------------------------------------
// BenchmarkComparisonAgent
// ---------------------------------------------------------------------------

/**
 * A benchmark comparison specialisation of {@link OffensiveSecurityAgent}.
 *
 * Compares expected security findings from a benchmark against actual
 * findings from a pentest session. Uses a single tool
 * (`provide_comparison_results`) to output the comparison.
 *
 * `consume()` returns a {@link BenchmarkComparisonResult}.
 */
export class BenchmarkComparisonAgent extends OffensiveSecurityAgent<BenchmarkComparisonResult> {
  constructor(opts: BenchmarkComparisonAgentInput) {
    const {
      model,
      repoPath,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      enableThinking,
      openAIReasoningEffort,
    } = opts;

    const expectedResults = loadExpectedResults(repoPath);
    const actualFindings = loadActualFindings(session.rootPath);
    const resultsPath = join(session.rootPath, "comparison-results.json");

    super({
      system: COMPARISON_SYSTEM_PROMPT,
      prompt: buildComparisonPrompt(expectedResults, actualFindings),
      model,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      enableThinking,
      openAIReasoningEffort,

      activeTools: ["provide_comparison_results"],

      stopWhen: [hasToolCall("provide_comparison_results"), stepCountIs(10000)],
      toolChoice: "auto",

      resolveResult: () => {
        let comparison: ComparisonResult | null = null;
        if (existsSync(resultsPath)) {
          try {
            comparison = JSON.parse(
              readFileSync(resultsPath, "utf-8"),
            ) as ComparisonResult;
          } catch {
            // May not have been written
          }
        }
        return { comparison, resultsPath };
      },
    });
  }
}

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

const COMPARISON_SYSTEM_PROMPT = `You are a security findings comparison agent. Your role is to compare expected security findings against actual findings from a penetration test and provide an accurate assessment.

# Your Task

You will be provided with:
1. **Expected findings** - A list of security vulnerabilities that should be found in the target application
2. **Actual findings** - The vulnerabilities that were actually discovered during the penetration test

Your job is to:
1. **Match findings** - Identify which actual findings correspond to expected findings
2. **Identify missed findings** - Expected findings that were not discovered
3. **Identify extra findings** - Actual findings that weren't in the expected list
4. **Calculate metrics** - Provide accuracy, precision, and recall scores

# Matching Criteria

When matching findings, consider:
- **Semantic similarity** - Do they describe the same vulnerability?
- **Severity alignment** - Do they have similar impact levels?
- **Category/type** - Are they the same type of vulnerability?
- **Location/context** - Are they in the same area of the application?

Don't require exact text matches — focus on whether they represent the same security issue.

# Important Notes

- Be generous with matching — if an actual finding clearly addresses an expected finding, count it
- Extra findings are NOT necessarily bad — they could be newly discovered vulnerabilities
- Focus on whether the pentest successfully identified the known vulnerabilities
- Provide clear explanations for why findings were matched or not matched

You MUST call the provide_comparison_results tool with your analysis.`;

// ---------------------------------------------------------------------------
// Prompt builder & helpers
// ---------------------------------------------------------------------------

function buildComparisonPrompt(
  expectedResults: Record<string, unknown>[],
  actualFindings: string,
): string {
  const expectedList = expectedResults
    .map(
      (r: Record<string, unknown>, i: number) =>
        `${i + 1}. **${r.title}** (${r.severity})\n   ${
          r.reason || r.description || ""
        }`,
    )
    .join("\n");

  return `## Expected Findings

${expectedList || "No expected findings found."}

## Actual Findings

${actualFindings || "No actual findings found."}

Analyze the findings above and call provide_comparison_results with your assessment.`;
}

function loadExpectedResults(repoPath: string): Record<string, unknown>[] {
  const expectedDir = join(repoPath, "expected_results");
  if (!existsSync(expectedDir)) return [];

  const results: Record<string, unknown>[] = [];

  for (const f of readdirSync(expectedDir).filter((f) => f.endsWith(".json"))) {
    try {
      const parsed = JSON.parse(readFileSync(join(expectedDir, f), "utf-8"));

      // Argus format: { vulnerabilities: [...] } with each vuln having name, severity, description, etc.
      if (parsed?.vulnerabilities && Array.isArray(parsed.vulnerabilities)) {
        for (const vuln of parsed.vulnerabilities) {
          results.push({
            title: vuln.vuln_name || vuln.name || vuln.title || "Unknown",
            severity: vuln.severity || "HIGH",
            reason:
              vuln.description_of_vuln || vuln.description || vuln.reason || "",
            ...vuln,
          });
        }
      } else if (parsed) {
        // Standard format: direct object with title, severity, reason
        results.push(parsed);
      }
    } catch {
      // skip unparseable files
    }
  }

  return results;
}

function loadActualFindings(sessionPath: string): string {
  const findingsDir = join(sessionPath, "findings");
  if (!existsSync(findingsDir)) return "No findings directory found.";

  const findings = readdirSync(findingsDir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => {
      try {
        const finding = JSON.parse(readFileSync(join(findingsDir, f), "utf-8"));
        return `### ${finding.title}
- **Severity:** ${finding.severity}
- **Endpoint:** ${finding.endpoint || "N/A"}
- **Category:** ${finding.vulnerabilityClass || finding.category || "N/A"}
- **Description:** ${finding.description || "N/A"}
- **Evidence:** ${finding.evidence || "N/A"}`;
      } catch {
        return null;
      }
    })
    .filter(Boolean);

  return findings.length > 0
    ? findings.join("\n\n")
    : "No findings were documented.";
}
