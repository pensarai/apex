import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

export function useSkill(ctx: ToolContext) {
  return tool({
    description: `Activate a skill from the skills catalog to load its detailed instructions and methodology.

Skills provide specialized testing procedures, checklists, and techniques.
Use this when you identify a testing scenario that matches an available skill.

The skill's full instructions will be returned — follow them to execute the methodology.`,
    inputSchema: z.object({
      name: z.string().describe("Skill slug from the skills catalog"),
      reason: z
        .string()
        .describe("Why this skill is relevant to the current task"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async ({ name, reason }) => {
      if (!ctx.skillsRegistry) {
        return { success: false, error: "Skills not available" };
      }

      try {
        const activated = ctx.skillsRegistry.activate(name);
        return {
          success: true,
          skill: activated.slug,
          reason,
          instructions: activated.instructions,
          scripts: activated.scripts.map((s) => ({
            name: s.name,
            path: s.path,
          })),
        };
      } catch (err) {
        return {
          success: false,
          error:
            err instanceof Error
              ? err.message
              : `Failed to activate skill "${name}"`,
        };
      }
    },
  });
}
