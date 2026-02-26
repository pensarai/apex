import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import { getQueryEngine } from "../../../knowledge/queryEngine";
import type { AttackCategory } from "../../../knowledge/attackKnowledge";

export function queryAttackKnowledge(_ctx: ToolContext) {
  return tool({
    description: `Search the attack knowledge base and get a map of matching techniques with file paths.

Returns a lightweight index of matching techniques — title, category, tags, a one-line summary, and the file path to the full technique JSON. Use \`read_file\` on the returned paths to pull in full details (payloads, steps, bypass methods) for techniques that look relevant to your objective. Use \`grep\` to search across technique files for specific keywords.

Search by:
- Category: ssrf, injection, auth_bypass, api, business_logic, ai_llm, client_side, race_condition, etc.
- Technology: node, python-flask, java-spring, postgresql, mongodb, etc.
- Context: url-parameter, json-body, api-endpoint, file-upload, etc.
- Free text: any keywords like "dns rebinding", "jwt", "race condition"`,
    inputSchema: z.object({
      category: z
        .string()
        .optional()
        .describe(
          "Attack category filter: injection, auth_bypass, ssrf, deserialization, xss, api, business_logic, ai_llm, client_side, race_condition, misconfiguration",
        ),
      technology: z
        .array(z.string())
        .optional()
        .describe(
          'Target technology stack, e.g. ["node", "postgresql", "express"]',
        ),
      context: z
        .string()
        .optional()
        .describe(
          "Attack context, e.g. url-parameter, json-body, api-endpoint, file-upload",
        ),
      freeText: z
        .string()
        .optional()
        .describe(
          'Free-text search across technique titles, tags, steps, and payloads, e.g. "jwt algorithm confusion" or "ssrf bypass cloud"',
        ),
      limit: z
        .number()
        .optional()
        .default(10)
        .describe("Maximum number of results to return (default: 10)"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise description of what you're searching for (e.g., 'Searching for SSRF bypass techniques')",
        ),
    }),
    execute: async ({ category, technology, context, freeText, limit }) => {
      const engine = getQueryEngine();

      const results = engine.query({
        category: category as AttackCategory | undefined,
        technology,
        context,
        freeText,
        limit,
      });

      if (results.length === 0) {
        return {
          success: true,
          count: 0,
          techniques: [],
          message:
            "No matching techniques found. Try broadening your search or using different keywords.",
        };
      }

      // Return a lightweight index — title, category, tags, summary, and file path.
      // The agent uses read_file on the paths to get full payloads/steps as needed.
      const techniques = results.map((r) => ({
        id: r.technique.id,
        title: r.technique.title,
        category: r.technique.category,
        tags: r.technique.tags,
        summary: r.technique.technique.summary,
        technologies: r.technique.applicability.technologies,
        filePath: r.filePath,
      }));

      return {
        success: true,
        count: techniques.length,
        techniques,
        message: `Found ${techniques.length} matching technique(s). Use read_file on the filePath values to get full payloads, steps, and bypass methods.`,
      };
    },
  });
}
