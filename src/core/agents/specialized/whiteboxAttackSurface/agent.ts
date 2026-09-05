import { stepCountIs, tool } from "ai";
import {
  OffensiveSecurityAgent,
  type SpecializedAgentInput,
} from "../../offSecAgent";
import { WHITEBOX_ATTACK_SURFACE_SYSTEM_PROMPT } from "./prompts";
import {
  type WhiteboxAttackSurfaceResult,
  WhiteboxAttackSurfaceResultSchema,
} from "./types";

const SUBMIT_RESULTS_TOOL_NAME = "submit_results";

/**
 * Safety cap on the agent loop. The run normally stops the instant
 * `submit_results` validates (see {@link WhiteboxAttackSurfaceAgent}); this only
 * guards against a model that never produces a valid submission.
 */
const WHITEBOX_MAX_STEPS = 10_000;

export const WHITEBOX_FALLBACK_RESULT: WhiteboxAttackSurfaceResult = {
  repoType: "unknown",
  packageManager: "unknown",
  apps: [],
  summary: {
    totalApps: 0,
    totalPages: 0,
    totalApiEndpoints: 0,
    totalPentestObjectives: 0,
  },
};

/**
 * Thrown when the model called `submit_results` but no attempt ever passed
 * schema validation, so {@link WhiteboxAttackSurfaceAgent} has no captured
 * result. Failing loud lets the caller retry or surface the error instead of
 * silently proceeding on an empty attack surface.
 */
export class WhiteboxSubmitValidationError extends Error {
  constructor() {
    super(
      "Whitebox attack surface recon called submit_results but no attempt passed " +
        "schema validation — refusing to silently return an empty attack surface. " +
        "The run should be retried.",
    );
    this.name = "WhiteboxSubmitValidationError";
  }
}

/**
 * Decide the final result once the run ends. Kept pure so the fail-loud vs.
 * empty-fallback decision is unit-testable without a live stream:
 * - a captured (validated) result is returned as-is;
 * - a `submit_results` call that never validated fails loud;
 * - a run where the model genuinely never submitted returns the empty fallback.
 */
export function finalizeWhiteboxResult(
  capturedResult: WhiteboxAttackSurfaceResult | null,
  submitAttempted: boolean,
): WhiteboxAttackSurfaceResult {
  if (capturedResult !== null) return capturedResult;
  if (submitAttempted) throw new WhiteboxSubmitValidationError();
  return WHITEBOX_FALLBACK_RESULT;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WhiteboxAttackSurfaceAgentInput extends SpecializedAgentInput {
  /** Root path of the codebase to analyze */
  codebasePath: string;
  /** Known domains associated with the project — agents can map discovered apps to these. */
  domains?: string[];
}

// ---------------------------------------------------------------------------
// WhiteboxAttackSurfaceAgent
// ---------------------------------------------------------------------------

/**
 * Orchestrator agent that maps the full attack surface of a codebase
 * by analyzing source code directly.
 *
 * Uses `spawn_coding_agent` to fan out app-level analysis, then
 * collects results via a structured `submit_results` tool injected
 * through `extraTools`.
 *
 * `consume()` returns a {@link WhiteboxAttackSurfaceResult} with all
 * discovered apps, endpoints, and pentest objectives.
 *
 * @example
 * ```ts
 * const agent = new WhiteboxAttackSurfaceAgent({
 *   codebasePath: "/app/target-project",
 *   model: "claude-sonnet-4-20250514",
 *   session,
 * });
 *
 * const result = await agent.consume({
 *   onTextDelta: (d) => process.stdout.write(d.text),
 *   onToolCall:  (d) => console.log(`→ ${d.toolName}`),
 * });
 *
 * console.log(`Found ${result.summary.totalApiEndpoints} API endpoints`);
 * ```
 */
export class WhiteboxAttackSurfaceAgent extends OffensiveSecurityAgent<WhiteboxAttackSurfaceResult> {
  constructor(opts: WhiteboxAttackSurfaceAgentInput) {
    const { codebasePath, domains, ...base } = opts;

    // The `submit_results` tool stashes the model's structured payload here and
    // `resolveResult` reads it back once the run ends — a per-run capture.
    let capturedResult: WhiteboxAttackSurfaceResult | null = null;

    super({
      ...base,
      system: WHITEBOX_ATTACK_SURFACE_SYSTEM_PROMPT,
      activeTools: [
        // Filesystem tools — for Phase 1 repo identification
        "read_file",
        "list_files",
        "grep",
        "document_app",
        "document_endpoint",
        // Orchestration — for Phase 2 app analysis
        "spawn_coding_agent",
        // Response tool (injected via extraTools)
        "submit_results",
      ],
      // Stop on a *successful* submission, not merely on the tool call. A
      // `submit_results` call whose arguments fail schema validation never sets
      // `capturedResult`, so the loop continues and the model gets another turn
      // to fix and resubmit (aided by tool-call repair). `stepCountIs` is only a
      // safety cap for a model that never produces a valid submission.
      stopWhen: [
        () => capturedResult !== null,
        stepCountIs(WHITEBOX_MAX_STEPS),
      ],
      extraTools: {
        ...base.extraTools,
        [SUBMIT_RESULTS_TOOL_NAME]: tool({
          description: `Submit the final whitebox attack surface analysis results.

Call this ONCE at the end with your complete structured findings.
This ends the agent run — make sure all data is included.`,
          inputSchema: WhiteboxAttackSurfaceResultSchema,
          execute: async (results) => {
            capturedResult = results;
            return { success: true, message: "Results submitted." };
          },
        }),
      },
      resolveResult: async (streamResult) => {
        // `capturedResult` is only set by a submission that passed validation.
        // If it's null but the model *did* call `submit_results` (the call was
        // rejected on a bad field), fail loud rather than masking the discarded
        // recon with an empty fallback.
        const steps = await streamResult.steps;
        const submitAttempted = steps.some((step) =>
          step.toolCalls.some(
            (call) => call.toolName === SUBMIT_RESULTS_TOOL_NAME,
          ),
        );
        return finalizeWhiteboxResult(capturedResult, submitAttempted);
      },
      prompt: buildPrompt(codebasePath, domains, base.session.config?.prompt),
    });
  }
}

// ---------------------------------------------------------------------------
// Prompt builder
// ---------------------------------------------------------------------------

function buildPrompt(
  codebasePath: string,
  domains?: string[],
  operatorPrompt?: string,
): string {
  const domainSection = domains?.length
    ? `\n## Known Domains
The following domains are **hints for association only** — they are known to be operated by the target and should be set on the \`domain\` field of \`document_app\` when you can determine which domain serves a given app.

**IMPORTANT — these domains DO NOT define the scope of discovery:**
- Discover and document **every** app/service/cloud resource defined in the codebase, regardless of whether it maps to one of these domains.
- Apps with no known public domain (internal services, background workers, staging-only apps, functions, admin tools, etc.) MUST still be documented. Leave \`domain\` unset or use the canonical resource URL for cloud resources.
- Do NOT filter out apps, endpoints, subdomains, or cloud resources because they don't appear to belong to one of these domains.
- Do NOT skip directories, packages, or services because they "look unrelated" to the listed domains.

Known domains:
${domains.map((d) => `- ${d}`).join("\n")}
`
    : "";
  const operatorGuidanceBlock = operatorPrompt
    ? `\n## Operator Guidance\n${operatorPrompt}\n`
    : "";

  return `# Whitebox Attack Surface Analysis

## Codebase
- **Path:** ${codebasePath}
${domainSection}${operatorGuidanceBlock}
## Task
Analyze this codebase and produce a complete attack surface map:
1. Identify the repo type and package manager
2. Discover all apps/services
3. Discover cloud resources and external infrastructure referenced in the code (S3 buckets, cloud storage, CDN origins, etc.) — document these as apps with the appropriate type
4. For each app, find all web pages and API endpoints (including gRPC methods — set \`transport\` and \`grpc\` on those endpoints so downstream testing uses the gRPC methodology instead of treating the wire path as HTTP)
5. For each endpoint, generate pentest objectives
6. **Before submitting**, perform the Phase 3 coverage double-check from the system prompt — re-scan workspace roots, framework configs, Dockerfiles, IaC, and CI/deploy configs for apps you may have missed on the first pass, and document any that were missed.

Use \`spawn_coding_agent\` to delegate app-level analysis for higher fidelity.

When finished, call \`submit_results\` with the complete structured output. Do NOT call \`submit_results\` until you have explicitly completed the coverage double-check.

Begin now.`;
}
