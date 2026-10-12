import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { addMemory as addTool } from "../agents/offSecAgent/tools/addMemory";
import { getMemory as getTool } from "../agents/offSecAgent/tools/getMemory";
import { listMemories as listTool } from "../agents/offSecAgent/tools/listMemories";
import type { ToolContext } from "../agents/offSecAgent/tools/types";
import { SessionInfoObject } from "../session";
import {
  addMemory,
  addMemoryWithId,
  deleteMemory,
  getMemory,
  listMemories,
  type Memory,
  type MemoryBackend,
  withMemoryBackend,
} from "./index";

function backend(name: string) {
  const entry: Memory = {
    id: name,
    title: name,
    content: name,
    category: "general",
    tags: [],
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
  };
  return {
    entry,
    add: vi.fn<MemoryBackend["add"]>().mockResolvedValue(entry),
    list: vi.fn<MemoryBackend["list"]>().mockResolvedValue([entry]),
    get: vi.fn<MemoryBackend["get"]>().mockResolvedValue(entry),
  };
}

const ctx: ToolContext = {
  session: SessionInfoObject.parse({
    id: "ses_test",
    version: "1",
    targets: [],
    time: { created: 0, updated: 0 },
    rootPath: "/tmp/test",
    logsPath: "/tmp/test/logs",
    findingsPath: "/tmp/test/findings",
    scratchpadPath: "/tmp/test/scratchpad",
    pocsPath: "/tmp/test/pocs",
  }),
  agentCwd: "/tmp/test",
  subagentSpawner: { spawn: vi.fn(), spawnMany: vi.fn() },
};
const executeAdd = addTool(ctx).execute;
const executeList = listTool(ctx).execute;
const executeGet = getTool(ctx).execute;
if (!executeAdd || !executeList || !executeGet)
  throw new Error("Memory tools must be executable");
const options = { toolCallId: "call-123", messages: [] };
const input = {
  title: "note",
  content: "details",
  toolCallDescription: "Save note",
};

describe("scoped memory backend", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("isolates overlapping hosts and inherits the backend in async child work", async () => {
    const first = backend("first");
    const second = backend("second");
    let release!: () => void;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    const pending = withMemoryBackend(first, async () => {
      await barrier;
      const child = async () => {
        await Promise.resolve();
        return getMemory("general", "first");
      };
      expect(await child()).toEqual(first.entry);
      expect(await addMemory(input)).toEqual(first.entry);
      expect(await listMemories()).toEqual([first.entry]);
    });
    await withMemoryBackend(second, async () => {
      expect(await addMemory(input)).toEqual(second.entry);
      release();
      await pending;
      expect(await listMemories()).toEqual([second.entry]);
    });
  });

  it("restores outer scope after a failure and filesystem storage outside hosts", async () => {
    const directory = await mkdtemp(join(tmpdir(), "memory-backend-"));
    vi.stubEnv("PENSAR_DATA_DIR", directory);
    vi.stubEnv("PENSAR_MEMORY_ENABLED", "true");
    try {
      const outer = backend("outer");
      await withMemoryBackend(outer, async () => {
        await expect(
          withMemoryBackend(backend("inner"), async () => {
            throw new Error("failed child");
          }),
        ).rejects.toThrow("failed child");
        expect(await listMemories()).toEqual([outer.entry]);
      });
      const saved = await addMemory(input);
      expect(await getMemory(saved.category, saved.id)).toEqual(saved);
      expect(await listMemories()).toHaveLength(1);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("forwards session and stable call identity on all memory tools", async () => {
    const host = backend("host");
    await withMemoryBackend(host, async () => {
      await executeAdd(input, options);
      await executeList(
        {
          category: "general",
          tag: "notes",
          toolCallDescription: "List notes",
        },
        options,
      );
      await executeGet(
        { category: "general", id: "host", toolCallDescription: "Get note" },
        options,
      );
    });
    const context = {
      sessionId: ctx.session.id,
      toolCallId: options.toolCallId,
    };
    expect(host.add).toHaveBeenCalledWith(
      {
        title: "note",
        content: "details",
        category: undefined,
        tags: undefined,
      },
      context,
    );
    expect(host.list).toHaveBeenCalledWith(
      { category: "general", tag: "notes" },
      context,
    );
    expect(host.get).toHaveBeenCalledWith("general", "host", context);
  });

  it("returns failure when hosted persistence fails, even with local memory disabled", async () => {
    vi.stubEnv("PENSAR_MEMORY_ENABLED", "false");
    const host = backend("host");
    host.add.mockRejectedValue(new Error("storage unavailable"));
    host.list.mockRejectedValue(new Error("storage unavailable"));
    host.get.mockRejectedValue(new Error("storage unavailable"));
    await withMemoryBackend(host, async () => {
      expect(await executeAdd(input, options)).toEqual({
        success: false,
        error: "storage unavailable",
      });
      expect(
        await executeList({ toolCallDescription: "List notes" }, options),
      ).toMatchObject({ success: false, error: "storage unavailable" });
      expect(
        await executeGet(
          { category: "general", id: "host", toolCallDescription: "Get note" },
          options,
        ),
      ).toMatchObject({ success: false, error: "storage unavailable" });
    });
  });

  it("does not use filesystem mutations inside a hosted scope", async () => {
    await withMemoryBackend(backend("host"), async () => {
      await expect(addMemoryWithId({ ...input, id: "fixed" })).rejects.toThrow(
        "only supported by filesystem memory",
      );
      await expect(deleteMemory("general", "fixed")).rejects.toThrow(
        "only supported by filesystem memory",
      );
    });
  });
});
