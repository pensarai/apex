import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

export function readSkill(ctx: ToolContext) {
  return tool({
    description:
      "Load a skill's full instructions by name from the available skills catalog.",
    inputSchema: z.object({
      name: z.string().describe("Skill slug from the available skills catalog"),
    }),
    execute: async ({ name }) => {
      if (!ctx.skillsRegistry) {
        return { success: false, error: "Skills not available" };
      }

      try {
        const { name: skillName, content } =
          await ctx.skillsRegistry.readSkillContent(name);
        return { success: true, name: skillName, content };
      } catch {
        const available = ctx.skillsRegistry
          .list()
          .map((e) => e.slug)
          .join(", ");
        return {
          success: false,
          error: `Unknown skill "${name}". Available: ${available}`,
        };
      }
    },
  });
}
