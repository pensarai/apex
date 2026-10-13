import { tool } from "ai";
import { z } from "zod";
import {
  listMemories as coreListMemories,
  MEMORY_CATEGORIES,
  type MemorySummary,
} from "../../../memory";
import type { ToolContext } from "./types";

const PAGE_SIZE = 20;
const PAGE_CHAR_BUDGET = 12_000;

const listMemoriesInputSchema = z.object({
  category: z
    .enum(MEMORY_CATEGORIES)
    .optional()
    .describe(
      'Filter by category: "app", "framework", or "general". ' +
        "Omit to list memories across all categories.",
    ),
  tag: z
    .string()
    .optional()
    .describe("Optional tag to filter memories by (exact match)"),
  cursor: z
    .object({
      createdAt: z.string(),
      category: z.enum(MEMORY_CATEGORIES),
      id: z.string(),
    })
    .optional()
    .describe("Pass the previous nextCursor to continue a listing"),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Listing stored recon notes')",
    ),
});

type ListMemoriesInput = z.infer<typeof listMemoriesInputSchema>;
type MemoryCursor = Pick<MemorySummary, "createdAt" | "category" | "id">;

export type ListMemoriesResult = {
  success: boolean;
  error: string;
  memories: Array<MemorySummary & { truncated?: true }>;
  count: number;
  nextCursor: MemoryCursor | null;
};

function compareMemories(a: MemoryCursor, b: MemoryCursor): number {
  const byCreatedAt = Date.parse(b.createdAt) - Date.parse(a.createdAt);
  if (byCreatedAt > 0 || byCreatedAt < 0) return byCreatedAt;
  return a.category.localeCompare(b.category) || a.id.localeCompare(b.id);
}

function previewSummary(memory: MemorySummary) {
  const title = memory.title.slice(0, 160);
  const tags = memory.tags.slice(0, 8).map((tag) => tag.slice(0, 48));
  const truncated =
    title.length < memory.title.length ||
    tags.length < memory.tags.length ||
    tags.some(
      (tag, index) => tag.length < (memory.tags[index]?.length ?? tag.length),
    );
  return {
    id: memory.id,
    category: memory.category,
    title,
    tags,
    createdAt: memory.createdAt,
    ...(truncated ? { truncated: true as const } : {}),
  };
}

export function listMemories(ctx: ToolContext) {
  return tool({
    description: `List saved memories, optionally filtered by category and/or tag.

Returns up to 20 lightweight summaries (id, category, title, tags, createdAt)
sorted by most recent first. Use nextCursor to continue until it is null;
count is the current total matching memories. A fresh listing includes newer
memories added ahead of a cursor. Titles and tags may be abbreviated in the
listing. Use category + id with get_memory to retrieve full content.`,
    inputSchema: listMemoriesInputSchema,
    execute: async (
      { category, tag, cursor },
      { toolCallId },
    ): Promise<ListMemoriesResult> => {
      try {
        const memories = await coreListMemories(
          { category, tag },
          { sessionId: ctx.session.id, toolCallId },
        );
        const ordered = [...memories].sort(compareMemories);
        let start = 0;
        if (cursor) {
          start = ordered.findIndex(
            (memory) => compareMemories(memory, cursor) > 0,
          );
          if (start < 0) start = ordered.length;
        }
        const page: ListMemoriesResult["memories"] = [];
        let pageChars = 0;
        for (const memory of ordered.slice(start, start + PAGE_SIZE)) {
          const summary = previewSummary(memory);
          const chars = JSON.stringify(summary).length + 1;
          if (page.length > 0 && pageChars + chars > PAGE_CHAR_BUDGET) break;
          page.push(summary);
          pageChars += chars;
        }
        const last = page.at(-1);
        return {
          success: true,
          error: "",
          memories: page,
          count: memories.length,
          nextCursor:
            start + page.length < ordered.length && last
              ? {
                  createdAt: last.createdAt,
                  category: last.category,
                  id: last.id,
                }
              : null,
        };
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          memories: [],
          count: 0,
          nextCursor: null,
        };
      }
    },
  });
}
