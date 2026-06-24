import { tool } from "ai";
import { z } from "zod";
import { getPromptInjectionLibrary } from "../../../prompt-injections";
import type { ToolContext } from "./types";

export function listPromptInjections(ctx: ToolContext) {
  return tool({
    description:
      "List available prompt-injection test payloads by safe metadata only. " +
      "The raw payload text is never returned. Use the returned id as a " +
      'PromptInjectionRef: {"kind":"prompt_injection_ref","id":"<id>"} when a tool supports runtime injection references.',
    inputSchema: z.object({
      category: z
        .string()
        .optional()
        .describe(
          "Optional category filter. Free-form string matched against the " +
            "catalog's category field (e.g. instruction-hijack, " +
            "data-exfiltration, tool-misuse, role-confusion, encoding). " +
            "Omit to list every category.",
        ),
      tag: z.string().optional().describe("Optional tag filter."),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of why you are listing prompt-injection payloads.",
        ),
    }),
    execute: async ({ category, tag }) => {
      let library: Awaited<ReturnType<typeof getPromptInjectionLibrary>>;
      try {
        library = await getPromptInjectionLibrary({
          library: ctx.promptInjectionLibrary,
          source: ctx.promptInjectionLibrarySource,
        });
      } catch (err) {
        // The catalog is externally curated; surface a concise, actionable
        // message instead of dumping a raw schema/parse error at the agent.
        return {
          success: false,
          configured: false,
          count: 0,
          injections: [],
          error: `Failed to load the prompt-injection library: ${
            err instanceof Error ? err.message : String(err)
          }`,
        };
      }

      const catalog = library.listCatalog();
      const injections = catalog
        .filter((entry) => !category || entry.category === category)
        .filter((entry) => !tag || entry.tags.includes(tag));

      return {
        success: true,
        configured: catalog.length > 0,
        count: injections.length,
        injections,
      };
    },
  });
}
