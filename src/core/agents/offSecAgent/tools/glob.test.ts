import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ToolBackends } from "../../../tools/backends/types";
import { type GlobResult, globFiles } from "./glob";
import type { ToolContext } from "./types";

function makeCtx(agentCwd: string): ToolContext {
  return {
    agentCwd,
    session: { id: "ses_test", rootPath: agentCwd },
  } as ToolContext;
}

describe("globFiles", () => {
  it("matches files by pattern and skips node_modules", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-glob-"));
    mkdirSync(join(root, "src"), { recursive: true });
    mkdirSync(join(root, "node_modules", "pkg"), { recursive: true });
    writeFileSync(join(root, "src", "a.ts"), "export {}");
    writeFileSync(join(root, "src", "b.tsx"), "export {}");
    writeFileSync(join(root, "node_modules", "pkg", "index.ts"), "export {}");

    const tool = globFiles(makeCtx(root));
    const result = (await tool.execute?.(
      {
        pattern: "**/*.{ts,tsx}",
        toolCallDescription: "Find TS sources",
      },
      { toolCallId: "t1", messages: [] },
    )) as GlobResult;

    expect(result.success).toBe(true);
    expect(result.files).toContain("src/a.ts");
    expect(result.files).toContain("src/b.tsx");
    expect(result.files.some((f: string) => f.includes("node_modules"))).toBe(
      false,
    );
  });

  it("rejects a search path that escapes agentCwd", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-glob-esc-"));
    const tool = globFiles(makeCtx(root));
    const result = (await tool.execute?.(
      {
        pattern: "**/*.ts",
        path: "../outside",
        toolCallDescription: "Escape attempt",
      },
      { toolCallId: "t1", messages: [] },
    )) as GlobResult;

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/escapes/);
  });

  it("calls the injected fs backend and never touches the host filesystem", async () => {
    const glob = vi.fn().mockResolvedValue({
      success: true,
      error: "",
      files: ["injected.ts"],
      count: 1,
      pattern: "**/*.ts",
      cwd: "/sandbox",
    } satisfies GlobResult);
    const backends = { fs: { glob } } as unknown as ToolBackends;

    const ctx = {
      agentCwd: "/sandbox",
      session: { id: "ses_test", rootPath: "/sandbox" },
      backends,
    } as ToolContext;

    const tool = globFiles(ctx);
    const result = (await tool.execute?.(
      { pattern: "**/*.ts", toolCallDescription: "Find sources" },
      { toolCallId: "t1", messages: [] },
    )) as GlobResult;

    expect(glob).toHaveBeenCalledWith("**/*.ts", { path: undefined });
    expect(result.files).toEqual(["injected.ts"]);
  });
});
