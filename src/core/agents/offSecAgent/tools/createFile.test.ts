import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ToolBackends } from "../../../tools/backends/types";
import { type CreateFileResult, createFile } from "./createFile";
import type { ToolContext } from "./types";

function makeCtx(agentCwd: string): ToolContext {
  return {
    agentCwd,
    session: { id: "ses_test", rootPath: agentCwd },
  } as ToolContext;
}

describe("createFile (golden, LocalBackends)", () => {
  it("creates a new file, making parent dirs", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-create-"));
    const tool = createFile(makeCtx(root));
    const result = (await tool.execute?.(
      {
        path: "sub/dir/new.ts",
        content: "export {}",
        toolCallDescription: "Create new.ts",
      },
      { toolCallId: "t1", messages: [] },
    )) as CreateFileResult;

    expect(result.success).toBe(true);
    expect(result.path).toBe(join(root, "sub/dir/new.ts"));
    expect(readFileSync(join(root, "sub/dir/new.ts"), "utf-8")).toBe(
      "export {}",
    );
  });

  it("refuses to overwrite an existing file by default", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-create-exist-"));
    const tool = createFile(makeCtx(root));
    await tool.execute?.(
      { toolCallDescription: "test", path: "a.ts", content: "one" },
      { toolCallId: "t1", messages: [] },
    );
    const result = (await tool.execute?.(
      { toolCallDescription: "test", path: "a.ts", content: "two" },
      { toolCallId: "t1", messages: [] },
    )) as CreateFileResult;

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/already exists/);
    expect(readFileSync(join(root, "a.ts"), "utf-8")).toBe("one");
  });

  it("overwrites when overwrite=true", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-create-overwrite-"));
    const tool = createFile(makeCtx(root));
    await tool.execute?.(
      { toolCallDescription: "test", path: "a.ts", content: "one" },
      { toolCallId: "t1", messages: [] },
    );
    const result = (await tool.execute?.(
      {
        toolCallDescription: "test",
        path: "a.ts",
        content: "two",
        overwrite: true,
      },
      { toolCallId: "t1", messages: [] },
    )) as CreateFileResult;

    expect(result.success).toBe(true);
    expect(readFileSync(join(root, "a.ts"), "utf-8")).toBe("two");
  });
});

describe("createFile backend injection", () => {
  it("calls the injected fs backend instead of writing to disk", async () => {
    const write = vi.fn().mockResolvedValue({
      success: true,
      error: "",
      path: "/sandbox/new.ts",
    } satisfies CreateFileResult);
    const backends = { fs: { write } } as unknown as ToolBackends;

    // A directory that does not exist on the host filesystem — if the tool
    // fell through to real I/O instead of the injected backend, writing
    // would fail (no such directory) instead of returning the mock's path.
    const ctx = {
      agentCwd: "/nonexistent/apex-sandbox-path",
      session: {
        id: "ses_test",
        rootPath: "/nonexistent/apex-sandbox-path",
      },
      backends,
    } as ToolContext;

    const tool = createFile(ctx);
    const result = (await tool.execute?.(
      {
        toolCallDescription: "test",
        path: "new.ts",
        content: "hi",
        overwrite: true,
      },
      { toolCallId: "t1", messages: [] },
    )) as CreateFileResult;

    expect(write).toHaveBeenCalledWith("new.ts", "hi", { mode: "overwrite" });
    expect(result.path).toBe("/sandbox/new.ts");
    expect(result.success).toBe(true);
  });
});
