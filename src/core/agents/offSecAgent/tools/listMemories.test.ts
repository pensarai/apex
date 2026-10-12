import { describe, expect, it, vi } from "vitest";
import {
  type Memory,
  type MemoryBackend,
  type MemorySummary,
  withMemoryBackend,
} from "../../../memory";
import { type GetMemoryResult, getMemory } from "./getMemory";
import { type ListMemoriesResult, listMemories } from "./listMemories";
import type { ToolContext } from "./types";

const ctx = { session: { id: "synthetic" } } as ToolContext;
const options = { toolCallId: "synthetic-call", messages: [] };
const list = listMemories(ctx).execute;
const get = getMemory(ctx).execute;
if (!list || !get) throw new Error("Memory tools must be executable");

describe("list_memories pagination", () => {
  it("continues from the first unreturned summary when the character budget fills", async () => {
    const summaries: MemorySummary[] = Array.from({ length: 30 }, (_, i) => ({
      id: `large-${i}`,
      category: "general",
      title: "t".repeat(300),
      tags: Array.from({ length: 8 }, () => "tag".repeat(40)),
      createdAt: new Date(Date.UTC(2026, 0, 1) - i * 1_000).toISOString(),
    }));
    const backend: MemoryBackend = {
      add: vi.fn(async () => {
        throw new Error("unexpected add");
      }),
      list: vi.fn(async () => summaries),
      get: vi.fn(async () => null),
    };
    await withMemoryBackend(backend, async () => {
      const first = (await list(
        { toolCallDescription: "List large synthetic memories" },
        options,
      )) as ListMemoriesResult;
      expect(first.memories.length).toBeLessThan(20);
      expect(JSON.stringify(first).length).toBeLessThan(12_500);
      expect(first.nextOffset).toBe(first.memories.length);
      const second = (await list(
        {
          offset: first.nextOffset ?? 0,
          toolCallDescription: "Continue large synthetic memories",
        },
        options,
      )) as ListMemoriesResult;
      expect(second.memories[0]?.id).toBe(summaries[first.memories.length]?.id);
    });
  });

  it("bounds each result while keeping every older memory discoverable", async () => {
    const summaries: MemorySummary[] = Array.from({ length: 200 }, (_, i) => ({
      id: `memory-${i}`,
      category: "general",
      title: `Memory ${i} ${"x".repeat(480)}`,
      tags: ["synthetic", "history"],
      createdAt: new Date(Date.UTC(2026, 0, 1) - i * 1_000).toISOString(),
    }));
    const backend: MemoryBackend = {
      add: vi.fn(async () => {
        throw new Error("unexpected add");
      }),
      list: vi.fn(async () =>
        summaries.map((summary, index) =>
          index === 0 ? { ...summary, content: "full-body-marker" } : summary,
        ),
      ),
      get: vi.fn(async (_category, id) => {
        const summary = summaries.find((item) => item.id === id);
        return summary
          ? ({
              ...summary,
              content: `Full ${id}`,
              updatedAt: summary.createdAt,
            } satisfies Memory)
          : null;
      }),
    };

    await withMemoryBackend(backend, async () => {
      const allIds: string[] = [];
      let offset = 0;
      let firstResultChars = 0;
      let pages = 0;
      for (;;) {
        const result = (await list(
          { offset, toolCallDescription: "List synthetic memories" },
          options,
        )) as ListMemoriesResult;
        expect(result.success).toBe(true);
        expect(result.count).toBe(200);
        expect(result.memories.length).toBeGreaterThan(0);
        expect(result.memories.length).toBeLessThanOrEqual(20);
        expect(JSON.stringify(result).length).toBeLessThan(12_500);
        if (pages === 0) {
          firstResultChars = JSON.stringify(result).length;
          expect(JSON.stringify(result)).not.toContain("full-body-marker");
          expect(result.memories[0]?.truncated).toBe(true);
          expect(result.memories[0]?.title.length).toBe(160);
        }
        allIds.push(...result.memories.map((memory) => memory.id));
        pages++;
        if (result.nextOffset === null) break;
        expect(result.nextOffset).toBeGreaterThan(offset);
        offset = result.nextOffset;
      }

      expect(allIds).toEqual(summaries.map((memory) => memory.id));
      const oldest = (await get(
        {
          category: "general",
          id: allIds.at(-1) ?? "",
          toolCallDescription: "Read oldest synthetic memory",
        },
        options,
      )) as GetMemoryResult;
      expect(oldest.memory?.content).toBe("Full memory-199");
      if (process.env.APEX_CONTEXT_BENCH === "1") {
        const previousChars = JSON.stringify({
          success: true,
          error: "",
          memories: summaries,
          count: summaries.length,
        }).length;
        console.log(
          "MEMORY_LIST_BENCH",
          JSON.stringify({ previousChars, firstResultChars, pages }),
        );
      }
    });
  });
});
