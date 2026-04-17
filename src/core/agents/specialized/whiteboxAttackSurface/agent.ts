import { tool } from "ai";
import { hasToolCall } from "ai";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import type { SpecializedAgentInput } from "../../offSecAgent/types";
import { WHITEBOX_ATTACK_SURFACE_SYSTEM_PROMPT } from "./prompts";
import {
  WhiteboxAttackSurfaceResultSchema,
  type WhiteboxAttackSurfaceResult,
} from "./types";

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
    const {
      model,
      codebasePath,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      eventBus,
      subagentId,
      attackSurfaceRegistry,
      domains,
      enableThinking,
    } = opts;

    // Closure variable that the response tool writes to
    let capturedResult: WhiteboxAttackSurfaceResult | null = null;

    // Build the structured response tool
    const submitResultsTool = tool({
      description: `Submit the final whitebox attack surface analysis results.

Call this ONCE at the end with your complete structured findings.
This ends the agent run — make sure all data is included.`,
      inputSchema: WhiteboxAttackSurfaceResultSchema,
      execute: async (results) => {
        capturedResult = results;
        return { success: true, message: "Results submitted." };
      },
    });

    super({
      system: WHITEBOX_ATTACK_SURFACE_SYSTEM_PROMPT,
      prompt: buildPrompt(codebasePath, domains, session.config?.prompt),
      model,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      eventBus,
      subagentId,
      attackSurfaceRegistry,
      enableThinking,
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

      extraTools: {
        submit_results: submitResultsTool,
      },

      stopWhen: hasToolCall("submit_results"),

      resolveResult: () => {
        if (capturedResult) {
          return capturedResult;
        }
        // Fallback if the agent didn't call submit_results
        return {
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
      },
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
4. For each app, find all web pages and API endpoints
5. For each endpoint, generate pentest objectives
6. **Before submitting**, perform the Phase 3 coverage double-check from the system prompt — re-scan workspace roots, framework configs, Dockerfiles, IaC, and CI/deploy configs for apps you may have missed on the first pass, and document any that were missed.

Use \`spawn_coding_agent\` to delegate app-level analysis for higher fidelity.

When finished, call \`submit_results\` with the complete structured output. Do NOT call \`submit_results\` until you have explicitly completed the coverage double-check.

Begin now.`;
}
