import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ToolBackends } from "../../../tools/backends/types";
import {
  type ApplyPatchResult,
  applyHunksToContent,
  applyPatch,
  parseUnifiedDiff,
} from "./applyPatch";
import type { ToolContext } from "./types";

function makeCtx(agentCwd: string): ToolContext {
  return {
    agentCwd,
    session: { id: "ses_test", rootPath: agentCwd },
  } as ToolContext;
}

describe("parseUnifiedDiff", () => {
  it("parses a single-file hunk", () => {
    const patch = `--- a/src/a.ts
+++ b/src/a.ts
@@ -1,3 +1,3 @@
 line1
-old
+new
 line3
`;
    const files = parseUnifiedDiff(patch);
    expect(files).toHaveLength(1);
    expect(files[0].oldPath).toBe("src/a.ts");
    expect(files[0].hunks).toHaveLength(1);
  });

  it("throws when the patch has no file diffs", () => {
    expect(() => parseUnifiedDiff("not a patch")).toThrow(/no file diffs/i);
  });
});

describe("applyHunksToContent", () => {
  it("applies a simple replacement", () => {
    const content = "line1\nold\nline3\n";
    const files = parseUnifiedDiff(`--- a/f
+++ b/f
@@ -1,3 +1,3 @@
 line1
-old
+new
 line3
`);
    const updated = applyHunksToContent(content, files[0].hunks);
    expect(updated).toBe("line1\nnew\nline3\n");
  });

  it("throws on context mismatch", () => {
    const content = "line1\nNOT_OLD\nline3\n";
    const files = parseUnifiedDiff(`--- a/f
+++ b/f
@@ -1,3 +1,3 @@
 line1
-old
+new
 line3
`);
    expect(() => applyHunksToContent(content, files[0].hunks)).toThrow(
      /context mismatch/i,
    );
  });
});

describe("applyPatch tool", () => {
  it("applies a multi-hunk patch to disk", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-"));
    writeFileSync(
      join(root, "file.ts"),
      "const a = 1;\nconst b = 2;\nconst c = 3;\n",
    );

    const patch = `--- a/file.ts
+++ b/file.ts
@@ -1,3 +1,3 @@
-const a = 1;
+const a = 10;
 const b = 2;
-const c = 3;
+const c = 30;
`;

    const tool = applyPatch(makeCtx(root));
    const result = (await tool.execute?.(
      { patch, toolCallDescription: "Bump constants" },
      { toolCallId: "t1", messages: [] },
    )) as ApplyPatchResult;

    expect(result.success).toBe(true);
    expect(result.files[0].success).toBe(true);
    expect(readFileSync(join(root, "file.ts"), "utf-8")).toBe(
      "const a = 10;\nconst b = 2;\nconst c = 30;\n",
    );
  });

  it("fails loudly and stops on a bad hunk", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-bad-"));
    writeFileSync(join(root, "file.ts"), "hello\n");

    const patch = `--- a/file.ts
+++ b/file.ts
@@ -1,1 +1,1 @@
-goodbye
+hi
`;

    const tool = applyPatch(makeCtx(root));
    const result = (await tool.execute?.(
      { patch, toolCallDescription: "Bad hunk" },
      { toolCallId: "t1", messages: [] },
    )) as ApplyPatchResult;

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Failed applying patch/);
    expect(readFileSync(join(root, "file.ts"), "utf-8")).toBe("hello\n");
  });
});

describe("applyPatch backend injection", () => {
  it("calls the injected fs backend instead of touching disk", async () => {
    const applyPatchFn = vi.fn().mockResolvedValue({
      success: true,
      error: "",
      files: [{ path: "file.ts", success: true, hunksApplied: 1 }],
    } satisfies ApplyPatchResult);
    const backends = {
      fs: { applyPatch: applyPatchFn },
    } as unknown as ToolBackends;

    // A directory that does not exist on the host filesystem — if the tool
    // fell through to real I/O instead of the injected backend, applying
    // the patch would fail (no such file) instead of returning the mock.
    const ctx = {
      agentCwd: "/nonexistent/apex-sandbox-path",
      session: {
        id: "ses_test",
        rootPath: "/nonexistent/apex-sandbox-path",
      },
      backends,
    } as ToolContext;

    const patch = "--- a/file.ts\n+++ b/file.ts\n@@ -1,1 +1,1 @@\n-old\n+new\n";
    const tool = applyPatch(ctx);
    const result = (await tool.execute?.(
      { toolCallDescription: "test", patch },
      { toolCallId: "t1", messages: [] },
    )) as ApplyPatchResult;

    expect(applyPatchFn).toHaveBeenCalledWith(patch);
    expect(result.files[0].path).toBe("file.ts");
  });
});
