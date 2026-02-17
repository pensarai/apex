import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import type { AttackSurfaceResult } from "../../specialized/attackSurface/blackboxAgent";

/**
 * Factory for the `run_attack_surface` tool.
 *
 * Launches a full {@link AttackSurfaceAgent} that autonomously maps
 * the target's attack surface — discovers assets, endpoints, auth
 * flows, and produces a structured list of targets for deep testing.
 *
 * This is Phase 1 of the {@link BlackboxPentestAgent} orchestration.
 */
export function runAttackSurface(ctx: ToolContext) {
  return tool({
    description: `Run the attack surface discovery agent to map the target's full attack surface.

This launches an autonomous sub-agent that will:
1. Enumerate endpoints, services, and assets
2. Detect and handle authentication flows
3. Crawl authenticated areas and extract JS endpoints
4. Produce a structured attack surface report with testable targets

Call this FIRST before spawn_pentest_swarm. The returned targets array
should be passed directly to spawn_pentest_swarm for deep testing.

Returns:
- targets: Array of {target, objective, rationale} for pentest agents
- results: Full attack surface analysis (assets, findings, summary)
- resultsPath: Path to the attack-surface-results.json file`,
    inputSchema: z.object({
      target: z.string().describe("The target to analyze (domain, IP, URL)"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async ({ target }) => {
      if (!ctx.model) {
        return {
          success: false,
          message: "run_attack_surface requires a model in the tool context.",
        };
      }

      const subagentId = "attack-surface-agent";

      try {
        // Dynamic import to break circular dependency:
        // AttackSurfaceAgent → OffensiveSecurityAgent → tools/index → runAttackSurface → AttackSurfaceAgent
        const { BlackboxAttackSurfaceAgent } =
          await import("../../specialized/attackSurface/blackboxAgent");

        const agent = new BlackboxAttackSurfaceAgent({
          target,
          model: ctx.model,
          session: ctx.session,
          authConfig: ctx.authConfig,
          abortSignal: ctx.abortSignal,
          callbacks: ctx.callbacks,
        });

        const result: AttackSurfaceResult = await agent.consume({
          onToolCall: (d) => console.log(`  [recon] → ${d.toolName}`),
          onToolResult: (d) => console.log(`  [recon] ✓ ${d.toolName}`),
          subagentCallbacks: ctx.subagentCallbacks
            ? {
                onTextDelta: (d) =>
                  ctx.subagentCallbacks!.onTextDelta?.({
                    ...d,
                    subagentId,
                  }),
                onToolCall: (d) =>
                  ctx.subagentCallbacks!.onToolCall?.({
                    ...d,
                    subagentId,
                  }),
                onToolResult: (d) =>
                  ctx.subagentCallbacks!.onToolResult?.({
                    ...d,
                    subagentId,
                  }),
                onError: (e) => ctx.subagentCallbacks!.onError?.(e),
              }
            : undefined,
        });

        const targetCount = result.targets.length;
        console.log(
          `\n✓ Attack surface complete: ${targetCount} targets identified`,
        );

        return {
          success: true,
          targets: result.targets.map((t) => ({
            target: t.target,
            objective: t.objective,
            rationale: t.rationale,
          })),
          totalTargets: targetCount,
          resultsPath: result.resultsPath,
          assetsPath: result.assetsPath,
          summary: result.results?.summary ?? null,
          keyFindings: result.results?.keyFindings ?? [],
          message: `Attack surface analysis complete. Discovered ${targetCount} targets for deep testing.`,
        };
      } catch (error: unknown) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        console.error(`✗ Attack surface agent failed: ${errorMsg}`);
        return {
          success: false,
          targets: [],
          totalTargets: 0,
          message: `Attack surface analysis failed: ${errorMsg}`,
        };
      }
    },
  });
}
