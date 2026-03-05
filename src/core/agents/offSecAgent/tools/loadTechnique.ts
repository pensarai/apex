import { z } from "zod";
import { tool } from "ai";
import {
  loadTechnique as loadTechniqueContent,
  getTechniquesCatalog,
} from "../../../techniques";

/**
 * Tool that lets agents dynamically load technique reference material at
 * runtime. The agent sees a catalog of available techniques in its system
 * prompt and calls this tool to pull in the ones relevant to its current
 * objectives.
 */
export function loadTechnique() {
  const available = getTechniquesCatalog().map((t) => t.name);

  return tool({
    description:
      `Load a technique reference by name. Returns the full technique content ` +
      `(attack methodology, detection signals, payloads, exploitation steps). ` +
      `Only load techniques that are relevant to your current objectives — ` +
      `each load adds context, so be selective. ` +
      `Available techniques: ${available.join(", ")}`,

    inputSchema: z.object({
      name: z
        .string()
        .describe(
          `The technique name to load (one of: ${available.join(", ")})`,
        ),
    }),

    execute: async ({ name }) => {
      try {
        const content = loadTechniqueContent(name);
        return {
          success: true,
          technique: name,
          content,
        };
      } catch (error) {
        return {
          success: false,
          error:
            error instanceof Error ? error.message : "Unknown error loading technique",
          availableTechniques: available,
        };
      }
    },
  });
}
