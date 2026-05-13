import { tool } from "ai";
import { z } from "zod";
import type { CatalogRecordKind } from "../../../whitebox";
import {
  profileCodebase,
  queryWhiteboxCatalog as queryCatalog,
} from "../../../whitebox";
import type { ToolContext } from "./types";

const CatalogKindSchema = z.enum([
  "entry-point",
  "trust-boundary",
  "sink",
  "scanner",
  "fuzzer",
  "review-pass",
  "verification",
]);

export function queryWhiteboxCatalog(ctx: ToolContext) {
  return tool({
    description: `Query the whitebox assessment catalog for focused source-analysis guidance.

Use this instead of asking for the whole playbook. Examples:
- "Node SSRF sinks"
- "Go fuzzing adapters"
- "Java deserialization verification"
- "authz tenant review pass"`,
    inputSchema: z.object({
      query: z.string().optional().describe("Search text"),
      kind: CatalogKindSchema.optional().describe(
        "Restrict by catalog record kind",
      ),
      tags: z
        .array(z.string())
        .optional()
        .describe("Tags that must be present"),
      limit: z.number().optional().describe("Maximum records to return"),
      toolCallDescription: z
        .string()
        .describe("A concise description of the catalog lookup"),
    }),
    execute: async ({ query, kind, tags, limit }) => {
      const rootPath = ctx.session.config?.codebasePath ?? ctx.agentCwd;
      const profile = await profileCodebase(rootPath).catch(() => undefined);
      const records = queryCatalog({
        profile,
        query,
        kind: kind as CatalogRecordKind | undefined,
        tags,
        limit,
      });

      return {
        success: true,
        summary: `Found ${records.length} whitebox catalog records.`,
        data: { records },
        artifactPaths: [],
        nextActions:
          records.length > 0
            ? [
                "Use the returned patterns with run_code_query for targeted source search.",
                "Create candidates only after tracing source-to-sink reachability.",
              ]
            : ["Broaden the query or omit kind/tags."],
        truncated: false,
      };
    },
  });
}
