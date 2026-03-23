import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import type { AttackSurfaceResult } from "../../specialized/attackSurface/blackboxAgent";
import type { WhiteboxAttackSurfaceResult } from "../../specialized/whiteboxAttackSurface/types";

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
    description:
      "Run attack surface discovery. Provide target (URL/domain for blackbox) or cwd (codebase path for whitebox). Call FIRST before spawn_pentest_swarm. Returns targets array for the swarm.",
    inputSchema: z.object({
      target: z.string().describe("Live target to analyze (domain, IP, URL)"),
      cwd: z
        .string()
        .optional()
        .describe(
          "Local codebase path — when provided, use whitebox attack surface analysis instead of blackbox",
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
      const cbs = ctx.subagentCallbacks;
      const subagentCallbacks = cbs
        ? {
            onTextDelta: (d: { type: "text-delta"; [k: string]: unknown }) =>
              cbs.onTextDelta?.({ ...d, subagentId } as never),
            onToolCallStreaming: (d: {
              toolCallId: string;
              toolName: string;
              [k: string]: unknown;
            }) => cbs.onToolCallStreaming?.({ ...d, subagentId } as never),
            onToolCallDelta: (d: {
              toolCallId: string;
              argsTextDelta: string;
              [k: string]: unknown;
            }) => cbs.onToolCallDelta?.({ ...d, subagentId } as never),
            onToolCall: (d: { type: "tool-call"; [k: string]: unknown }) =>
              cbs.onToolCall?.({ ...d, subagentId } as never),
            onToolResult: (d: { type: "tool-result"; [k: string]: unknown }) =>
              cbs.onToolResult?.({ ...d, subagentId } as never),
            onError: (e: unknown) => cbs.onError?.(e),
          }
        : undefined;

      cbs?.onSubagentSpawn?.({
        subagentId,
        input: { target, cwd },
        status: "pending",
      });

      // -----------------------------------------------------------------------
      // Whitebox mode — analyze source code (cwd is the indicator)
      // -----------------------------------------------------------------------
      if (cwd) {
        try {
          const { WhiteboxAttackSurfaceAgent } =
            await import("../../specialized/whiteboxAttackSurface/agent");

          const agent = new WhiteboxAttackSurfaceAgent({
            codebasePath: cwd,
            model: ctx.model,
            session: ctx.session,
            authConfig: ctx.authConfig,
            abortSignal: ctx.abortSignal,
            attackSurfaceRegistry: ctx.attackSurfaceRegistry,
            callbacks: ctx.callbacks,
          });

          const result: WhiteboxAttackSurfaceResult = await agent.consume({
            onToolCall: (d) =>
              console.log(`  [recon:whitebox] → ${d.toolName}`),
            onToolResult: (d) =>
              console.log(`  [recon:whitebox] ✓ ${d.toolName}`),
            subagentCallbacks,
          });

          // Flatten whitebox results into the same targets shape the swarm expects
          const targets = result.apps.flatMap((app) =>
            [...app.pages, ...app.apiEndpoints].map((ep) => ({
              target: ep.path,
              objective: ep.pentestObjectives.join("; "),
              rationale: `${app.framework} ${ep.method} endpoint in ${app.name} (${ep.file}${ep.line ? `:${ep.line}` : ""})`,
            })),
          );

          console.log(
            `\n✓ Whitebox attack surface complete: ${targets.length} targets from ${result.apps.length} apps`,
          );

          cbs?.onSubagentComplete?.({
            subagentId,
            input: { target, cwd },
            status: "completed",
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
          console.error(`✗ Whitebox attack surface agent failed: ${errorMsg}`);

          cbs?.onSubagentComplete?.({
            subagentId,
            input: { target, cwd },
            status: "failed",
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
        const { BlackboxAttackSurfaceAgent } =
          await import("../../specialized/attackSurface/blackboxAgent");

        const agent = new BlackboxAttackSurfaceAgent({
          target: target!,
          model: ctx.model,
          session: ctx.session,
          authConfig: ctx.authConfig,
          abortSignal: ctx.abortSignal,
          attackSurfaceRegistry: ctx.attackSurfaceRegistry,
          callbacks: ctx.callbacks,
        });

        const result: AttackSurfaceResult = await agent.consume({
          onToolCall: (d) => console.log(`  [recon:blackbox] → ${d.toolName}`),
          onToolResult: (d) =>
            console.log(`  [recon:blackbox] ✓ ${d.toolName}`),
          subagentCallbacks,
        });

        const targetCount = result.targets.length;
        console.log(
          `\n✓ Blackbox attack surface complete: ${targetCount} targets identified`,
        );

        cbs?.onSubagentComplete?.({
          subagentId,
          input: { target },
          status: "completed",
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
        console.error(`✗ Blackbox attack surface agent failed: ${errorMsg}`);

        cbs?.onSubagentComplete?.({
          subagentId,
          input: { target },
          status: "failed",
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
