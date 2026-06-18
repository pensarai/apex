import { tool } from "ai";
import { z } from "zod";
import { AgentEventBus } from "../../../eventBus";
import { createLogger } from "../../../logger/structured";
import { scopedLogger } from "../../../util/lazyLogger";
import type { AttackSurfaceResult } from "../../specialized/attackSurface/blackboxAgent";
import type { WhiteboxAttackSurfaceResult } from "../../specialized/whiteboxAttackSurface";
import type { ToolContext } from "./types";

const log = scopedLogger(() => createLogger("run_attack_surface"));

/**
 * Factory for the `run_attack_surface` tool.
 *
 * Launches either a **blackbox** or **whitebox** attack surface agent
 * depending on whether `target` (live URL) or `cwd` (codebase path) is
 * provided.
 *
 * This is Phase 1 of the {@link PentestAgent} orchestration.
 */
export function runAttackSurface(ctx: ToolContext) {
  return tool({
    description: `Run the attack surface discovery agent to map the target's full attack surface.

Provide exactly ONE of:
- target: a live URL/domain/IP for blackbox analysis (probes the running service)
- cwd: a local codebase path for whitebox analysis (reads source code directly)

BLACKBOX mode launches a sub-agent that probes the live target to discover
endpoints, authentication flows, and assets.

WHITEBOX mode launches a sub-agent that analyzes source code to discover
all apps, endpoints, pages, and generates pentest objectives from the code.

Call this FIRST before spawn_pentest_swarm. The returned targets array
should be passed directly to spawn_pentest_swarm for deep testing.`,
    inputSchema: z.object({
      target: z.string().describe("Live target to analyze (domain, IP, URL)"),
      cwd: z
        .string()
        .optional()
        .describe(
          "Local codebase path — when provided, use whitebox attack surface analysis instead of blackbox",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async ({ target, cwd }) => {
      if (!ctx.model) {
        return {
          success: false,
          message: "run_attack_surface requires a model in the tool context.",
        };
      }

      const subagentId = "attack-surface-agent";

      ctx.eventBus?.emit("subagent-spawn", {
        subagentId,
        input: { target, cwd },
        parentSubagentId: ctx.subagentId,
      });

      // -----------------------------------------------------------------------
      // Whitebox mode — analyze source code (cwd is the indicator)
      // -----------------------------------------------------------------------
      if (cwd) {
        try {
          const { WhiteboxAttackSurfaceAgent } = await import(
            "../../specialized/whiteboxAttackSurface"
          );

          const localBus = new AgentEventBus();
          AgentEventBus.attachChild(localBus, ctx.eventBus, subagentId);

          const agent = new WhiteboxAttackSurfaceAgent({
            codebasePath: cwd,
            model: ctx.model,
            session: ctx.session,
            authConfig: ctx.authConfig,
            abortSignal: ctx.abortSignal,
            attackSurfaceRegistry: ctx.attackSurfaceRegistry,
            eventBus: localBus,
            subagentId,
          });

          const result: WhiteboxAttackSurfaceResult = await agent.consume();

          // Flatten whitebox results into the same targets shape the swarm expects
          const targets = result.apps.flatMap((app) =>
            [...app.pages, ...app.apiEndpoints].map((ep) => ({
              target: ep.path,
              objective: ep.pentestObjectives.join("; "),
              rationale: `${app.framework} ${ep.method} endpoint in ${app.name} (${ep.file}${ep.line ? `:${ep.line}` : ""})`,
            })),
          );

          log.info(
            `Whitebox attack surface complete: ${targets.length} targets from ${result.apps.length} apps`,
          );

          ctx.eventBus?.emit("subagent-complete", {
            subagentId,
            status: "completed",
            parentSubagentId: ctx.subagentId,
          });

          return {
            success: true,
            mode: "whitebox" as const,
            targets,
            totalTargets: targets.length,
            summary: result.summary,
            message: `Whitebox analysis complete. ${result.summary.totalApps} apps, ${result.summary.totalApiEndpoints} API endpoints, ${result.summary.totalPages} pages.`,
          };
        } catch (error: unknown) {
          const errorMsg =
            error instanceof Error ? error.message : String(error);
          log.error(`Whitebox attack surface agent failed: ${errorMsg}`);

          ctx.eventBus?.emit("subagent-complete", {
            subagentId,
            status: "failed",
            parentSubagentId: ctx.subagentId,
          });

          return {
            success: false,
            targets: [],
            totalTargets: 0,
            message: `Whitebox attack surface analysis failed: ${errorMsg}`,
          };
        }
      }

      // -----------------------------------------------------------------------
      // Blackbox mode — probe live target
      // -----------------------------------------------------------------------
      try {
        const { BlackboxAttackSurfaceAgent } = await import(
          "../../specialized/attackSurface/blackboxAgent"
        );

        const localBus = new AgentEventBus();
        AgentEventBus.attachChild(localBus, ctx.eventBus, subagentId);

        const agent = new BlackboxAttackSurfaceAgent({
          target: target!,
          model: ctx.model,
          session: ctx.session,
          authConfig: ctx.authConfig,
          abortSignal: ctx.abortSignal,
          attackSurfaceRegistry: ctx.attackSurfaceRegistry,
          eventBus: localBus,
          subagentId,
        });

        const result: AttackSurfaceResult = await agent.consume();

        const targetCount = result.targets.length;
        log.info(
          `Blackbox attack surface complete: ${targetCount} targets identified`,
        );

        ctx.eventBus?.emit("subagent-complete", {
          subagentId,
          status: "completed",
          parentSubagentId: ctx.subagentId,
        });

        return {
          success: true,
          mode: "blackbox" as const,
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
          message: `Blackbox analysis complete. Discovered ${targetCount} targets for deep testing.`,
        };
      } catch (error: unknown) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        log.error(`Blackbox attack surface agent failed: ${errorMsg}`);

        ctx.eventBus?.emit("subagent-complete", {
          subagentId,
          status: "failed",
          parentSubagentId: ctx.subagentId,
        });

        return {
          success: false,
          targets: [],
          totalTargets: 0,
          message: `Blackbox attack surface analysis failed: ${errorMsg}`,
        };
      }
    },
  });
}
