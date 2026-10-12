import { describe, expect, it, vi } from "vitest";
import { LocalBackends } from "../../../tools/backends/local";
import { gitStatus } from "./gitStatus";
import type { ToolContext } from "./types";
import { updateFile } from "./updateFile";

const options = { toolCallId: "test", messages: [] };
function context(): ToolContext {
  const ctx = {
    agentCwd: "/workspace",
    session: { rootPath: "/workspace" },
  } as ToolContext;
  ctx.backends = LocalBackends(ctx);
  return ctx;
}
it("passes the exact original content to injected writes for optimistic concurrency", async () => {
  const ctx = context();
  vi.spyOn(ctx.backends!.fs, "readRaw").mockResolvedValue({
    success: true,
    content: "before\r\n",
    path: "/workspace/a",
    error: "",
  });
  const write = vi.spyOn(ctx.backends!.fs, "write").mockResolvedValue({
    success: false,
    path: "/workspace/a",
    error: "changed since read",
  });
  const result = await updateFile(ctx).execute!(
    {
      path: "a",
      oldContent: "before",
      newContent: "after",
      toolCallDescription: "test",
    },
    options,
  );
  expect(write).toHaveBeenCalledWith("/workspace/a", "after\r\n", {
    mode: "overwrite",
    expected: "before\r\n",
  });
  expect(result).toMatchObject({
    success: false,
    replacements: 0,
    error: "changed since read",
  });
});
describe("injected git status capture", () => {
  it("never reports an empty truncated status as clean", async () => {
    const ctx = context();
    vi.spyOn(ctx.backends!.fs, "git").mockResolvedValue({
      success: true,
      stdout: "",
      stderr: "",
      stdoutTruncated: true,
      cwd: "/workspace",
    });
    const result = await gitStatus(ctx).execute!(
      { toolCallDescription: "test" },
      options,
    );
    expect(result).toMatchObject({ success: true });
    expect(JSON.stringify(result)).toContain("INCOMPLETE");
    expect(JSON.stringify(result)).not.toContain("(clean)");
  });
});
