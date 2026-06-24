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
        .enum([
          "instruction-hijack",
          "data-exfiltration",
          "tool-misuse",
          "role-confusion",
          "encoding",
        ])
        .optional()
        .describe("Optional category filter."),
      tag: z.string().optional().describe("Optional tag filter."),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of why you are listing prompt-injection payloads.",
        ),
    }),
    execute: async ({ category, tag }) => {
      const library = await getPromptInjectionLibrary({
        library: ctx.promptInjectionLibrary,
        source: ctx.promptInjectionLibrarySource,
      });
      const injections = library
        .listCatalog()
        .filter((entry) => !category || entry.category === category)
        .filter((entry) => !tag || entry.tags.includes(tag));

      return {
        success: true,
        configured: library.listCatalog().length > 0,
        count: injections.length,
        injections,
      };
    },
  });
}
