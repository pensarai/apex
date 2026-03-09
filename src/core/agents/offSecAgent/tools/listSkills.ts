import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

export function listSkills(ctx: ToolContext) {
  return tool({
    description: `List all available skills from the skills catalog.

Returns the full catalog of skills with their names, descriptions, and tags.
Useful when the initial system prompt catalog has been summarized away,
or to check what skills are currently active.`,
    inputSchema: z.object({
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async () => {
      if (!ctx.skillsRegistry) {
        return { success: false, error: "Skills not available", skills: [] };
      }

      const enabled = ctx.skillsRegistry.listEnabled();
      let activeCount = 0;

      const skills = enabled.map((entry) => {
        const isActive = ctx.skillsRegistry!.isActive(entry.slug);
        if (isActive) activeCount++;
        return {
          slug: entry.slug,
          name: entry.manifest.name,
          description: entry.manifest.description,
          tags: entry.manifest.tags ?? [],
          source: entry.source,
          active: isActive,
          hasScripts: entry.scripts.length > 0,
        };
      });

      return {
        success: true,
        skills,
        totalCount: enabled.length,
        activeCount,
      };
    },
  });
}
