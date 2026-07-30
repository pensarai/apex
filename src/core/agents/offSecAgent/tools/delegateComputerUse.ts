import { tool } from "ai";
import { z } from "zod";
import { AgentEventBus } from "../../../eventBus";
import { newSessionId } from "../../../id/id";
import { createLogger } from "../../../logger/structured";
import { scopedLogger } from "../../../util/lazyLogger";
import type { ToolContext } from "./types";

const log = scopedLogger(() => createLogger("delegate_computer_use"));

// ComputerUseAgent is dynamically imported inside execute() to break the
// circular dependency: computerUseAgent → offensiveSecurityAgent → tools/index
// → delegateComputerUse → computerUseAgent. The `class extends` clause is
// evaluated at module load, so a static import would resolve
// OffensiveSecurityAgent to `undefined` mid-cycle (mirrors delegateAuth).

/**
 * Factory for the `delegate_to_computer_use_agent` tool.
 *
 * Delegates GUI interaction to the specialized {@link ComputerUseAgent}, which
 * drives the already-launched application under test via desktop automation
 * tools (screenshot, mouse, keyboard). Requires `model` in the tool context.
 */
export function delegateComputerUse(ctx: ToolContext) {
  return tool({
    description: `Delegate a task to the Computer Use subagent for desktop GUI interaction.

Use when you need to interact with a graphical application under test that
cannot be driven via CLI or the browser tools — thick/native clients, embedded
UIs, native OS dialogs, or any workflow that requires visually observing the
screen and clicking / typing.

The application under test is already installed and launched. The subagent will:
1. Take screenshots to observe the desktop.
2. Click, double-click, and drag with the mouse.
3. Type text and press key combinations.
4. Scroll and navigate within the application.

Provide a clear, specific objective describing what to accomplish on the desktop.

NOTE: Requires a graphical desktop (X11 on Linux, Aqua on macOS, a Windows
desktop session). It will not work in a headless environment with no display.`,
    inputSchema: z.object({
      objective: z
        .string()
        .describe(
          "Detailed description of what the agent should accomplish on the desktop",
        ),
      context: z
        .string()
        .optional()
        .describe(
          "Additional context about the target application or desktop state",
        ),
      toolCallDescription: z
        .string()
        .describe("A concise description of what this tool call is doing"),
    }),
    execute: async ({ objective, context }) => {
      const subagentId = newSessionId();
      const subagentName = "Computer Use Agent";

      if (!ctx.model) {
        return {
          success: false,
          message:
            "delegate_to_computer_use_agent requires a model in the tool context.",
          output: "",
        };
      }

      ctx.eventBus?.emit("subagent-spawn", {
        subagentId,
        name: subagentName,
        input: { objective },
        parentSubagentId: ctx.subagentId,
      });

      const localBus = new AgentEventBus();
      AgentEventBus.attachChild(localBus, ctx.eventBus, subagentId);

      try {
        log.info("Delegating to computer-use subagent", { objective });

        const { ComputerUseAgent } = await import(
          "../../specialized/computerUseAgent"
        );

        const agent = new ComputerUseAgent({
          objective,
          context,
          model: ctx.model,
          session: ctx.session,
          authConfig: ctx.authConfig,
          abortSignal: ctx.abortSignal,
          secretValues: ctx.secretValues,
          eventBus: localBus,
          subagentId,
          subagentName,
        });

        const result = await agent.consume();

        ctx.eventBus?.emit("subagent-complete", {
          subagentId,
          status: result?.status === "failed" ? "failed" : "completed",
          parentSubagentId: ctx.subagentId,
        });

        return {
          success: result?.status !== "failed",
          message:
            result?.status === "failed"
              ? "Computer use agent could not complete the task."
              : "Computer use agent completed the task.",
          output: result?.summary ?? "",
        };
      } catch (error) {
        ctx.eventBus?.emit("subagent-complete", {
          subagentId,
          status: "failed",
          parentSubagentId: ctx.subagentId,
        });
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        return {
          success: false,
          message: `Computer use agent failed: ${errorMessage}`,
          output: "",
        };
      }
    },
  });
}
