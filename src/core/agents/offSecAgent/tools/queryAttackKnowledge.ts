import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import { getQueryEngine } from "../../../knowledge/queryEngine";
import type { AttackCategory } from "../../../knowledge/attackKnowledge";

export function queryAttackKnowledge(_ctx: ToolContext) {
  return tool({
    description: `Query the attack knowledge base for offensive techniques, payloads, and bypass methods.

Use this tool to find relevant attack techniques based on:
- Category (ssrf, injection, auth_bypass, api, business_logic, ai_llm, client_side, etc.)
- Technology stack (node, python-flask, java-spring, etc.)
- Context (url-parameter, json-body, api-endpoint, file-upload, etc.)
- Free text search (any keywords like "dns rebinding", "jwt", "race condition")

The knowledge base contains curated techniques with concrete payloads, step-by-step exploitation guides, and WAF bypass methods. Query it before crafting payloads to leverage known-good techniques.`,
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
        .default(5)
        .describe("Maximum number of results to return (default: 5)"),
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

      // Return structured results with full technique details
      const techniques = results.map((t) => ({
        id: t.id,
        title: t.title,
        category: t.category,
        tags: t.tags,
        summary: t.technique.summary,
        steps: t.technique.steps,
        payloads: t.technique.payloads,
        bypassTechniques: t.technique.bypassTechniques,
        applicability: t.applicability,
        references: t.references,
      }));

      return {
        success: true,
        count: techniques.length,
        techniques,
        message: `Found ${techniques.length} matching technique(s).`,
      };
    },
  });
}
