import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import { AgentEventBus, type AgentEventMap } from "../../../eventBus";

const CHILD_BUS_EVENT_KEYS = [
  "text-delta",
  "tool-call-start",
  "tool-call-delta",
  "tool-call-complete",
  "tool-result",
  "subagent-spawn",
  "subagent-complete",
  "command-output",
  "error",
] as const satisfies readonly (keyof AgentEventMap)[];

function attachChildEventBus(
  localBus: AgentEventBus,
  parentBus: AgentEventBus | undefined,
  accumulateText: (chunk: string) => void,
): void {
  for (const key of CHILD_BUS_EVENT_KEYS) {
    localBus.on(key, (payload: AgentEventMap[typeof key]) => {
      if (key === "text-delta") {
        accumulateText((payload as AgentEventMap["text-delta"]).text);
      }
      parentBus?.emit(key, payload);
    });
  }
}

/**
 * Factory for the `delegate_to_computer_use_agent` tool.
 *
 * Delegates GUI interaction tasks to the specialized Computer Use subagent.
 * The subagent has access to desktop automation tools (screenshot, mouse,
 * keyboard) and can interact with graphical applications autonomously.
 */
export function delegateComputerUse(ctx: ToolContext) {
  return tool({
    description: `Delegate a task to the Computer Use subagent for GUI interaction.

Use when:
- Need to interact with a graphical desktop application (thick client, Java app, etc.)
- Testing via VNC/RDP session that requires visual interaction
- Automating a GUI workflow that cannot be done via CLI or browser tools
- Need to take screenshots and visually verify desktop state
- Interacting with native OS dialogs, file managers, or system UIs

The computer use agent can:
1. Take screenshots to observe the desktop
2. Click, double-click, and drag with the mouse
3. Type text and press key combinations
4. Scroll and navigate within applications
5. Get screen dimensions and active window info

Provide a clear, specific objective describing what the agent should accomplish
on the desktop. The agent will use screenshots to orient itself and perform
the requested interaction autonomously.

NOTE: Requires a graphical desktop environment (X11 on Linux, Aqua on macOS).
Will not work in headless/SSH-only environments without a display.`,
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
      if (!ctx.model) {
        return {
          success: false,
          message:
            "delegate_to_computer_use_agent requires a model in the tool context.",
          output: "",
        };
      }

      const subagentId = "computer-use-agent";

      ctx.eventBus?.emit("subagent-spawn", {
        subagentId,
        name: "Computer Use",
        input: { objective },
      });

      const localBus = new AgentEventBus();
      let textOutput = "";
      attachChildEventBus(localBus, ctx.eventBus, (t) => {
        textOutput += t;
      });

      try {
        // Dynamic import to break circular dependency
        const { ComputerUseAgent } =
          await import("../../specialized/computerUseAgent/agent");

        const agent = new ComputerUseAgent({
          objective,
          context,
          model: ctx.model,
          session: ctx.session,
          authConfig: ctx.authConfig,
          abortSignal: ctx.abortSignal,
          eventBus: localBus,
          subagentId,
        });

        await agent.consume();

        ctx.eventBus?.emit("subagent-complete", {
          subagentId,
          status: "completed",
        });

        return {
          success: true,
          message: `Computer use agent completed the task.`,
          output: textOutput,
        };
      } catch (error) {
        ctx.eventBus?.emit("subagent-complete", {
          subagentId,
          status: "failed",
        });

        const errorMessage =
          error instanceof Error ? error.message : String(error);
        return {
          success: false,
          message: `Computer use agent failed: ${errorMessage}`,
          output: textOutput,
        };
      }
    },
  });
}
