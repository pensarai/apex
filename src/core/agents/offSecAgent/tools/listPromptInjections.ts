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
          "Optional category filter. Returns only payloads whose `category` " +
            "field matches this value exactly (case-sensitive). The library is " +
            "externally curated, so categories vary; common ones include " +
            "instruction-hijack, data-exfiltration, tool-misuse, role-confusion, " +
            "and encoding. Call the tool once without filters first to discover " +
            "the exact category strings available, then re-call with one of them. " +
            "Omit to list payloads from every category.",
        ),
      tag: z
        .string()
        .optional()
        .describe(
          "Optional tag filter. Returns only payloads whose `tags` array " +
            "contains this exact tag (case-sensitive). Tags are free-form labels " +
            'defined by the library (e.g. "baseline", "encoding", "secrets"); ' +
            "inspect the `tags` on an unfiltered listing to find valid values. " +
            "Combine with `category` to narrow results further. Omit to ignore tags.",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description (one short sentence) of why " +
            "you are listing prompt-injection payloads right now, e.g. " +
            '"Finding tool-misuse payloads to test the support-ticket endpoint". ' +
            "Shown in the run timeline for auditability.",
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
