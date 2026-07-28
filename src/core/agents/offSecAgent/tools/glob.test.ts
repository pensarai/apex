import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { type GlobResult, globFiles, resolveGlobRoot } from "./glob";
import type { ToolContext } from "./types";

function makeCtx(agentCwd: string): ToolContext {
  return {
    agentCwd,
    session: { id: "ses_test", rootPath: agentCwd },
  } as ToolContext;
}

describe("resolveGlobRoot", () => {
  it("defaults to agentCwd", () => {
    expect(resolveGlobRoot("/repo")).toBe("/repo");
  });

  it("rejects paths that escape agentCwd", () => {
    expect(() => resolveGlobRoot("/repo", "../outside")).toThrow(/escapes/);
  });
});

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
});
