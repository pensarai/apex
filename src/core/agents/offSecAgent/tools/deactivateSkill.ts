import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

export function deactivateSkill(ctx: ToolContext) {
  return tool({
    description: `Deactivate a previously activated skill, removing its instructions from the active context.

Use this when you have completed the skill's methodology or it is no longer relevant
to the current testing phase.`,
    inputSchema: z.object({
      name: z.string().describe("Skill slug to deactivate"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async ({ name }) => {
      if (!ctx.skillsRegistry) {
        return { success: false, error: "Skills not available" };
      }

      if (!ctx.skillsRegistry.isActive(name)) {
        return {
          success: false,
          error: `Skill "${name}" is not currently active`,
        };
      }

      ctx.skillsRegistry.deactivate(name);
      return { success: true, skill: name, status: "deactivated" };
    },
  });
}
