import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import {
  type ApplyPatchResult,
  applyPatch,
  duplicateTargetKey,
} from "./applyPatch";
import type { UnifiedSandbox } from "./sandbox";
import type { ToolContext } from "./types";

const execute = promisify(execFile);

function makeCtx(
  agentCwd: string,
  extra: Partial<ToolContext> = {},
): ToolContext {
  return {
    agentCwd,
    session: { id: "ses_test", rootPath: agentCwd },
    ...extra,
  } as ToolContext;
}

async function run(ctx: ToolContext, patch: string): Promise<ApplyPatchResult> {
  const tool = applyPatch(ctx);
  return (await tool.execute?.(
    { patch, toolCallDescription: "test patch" },
    { toolCallId: "t1", messages: [] },
  )) as ApplyPatchResult;
}

const linuxSandbox: UnifiedSandbox = {
  type: "linux",
  async execute(command, options) {
    const { stdout, stderr } = await execute("/bin/sh", ["-c", command], {
      cwd: options?.cwd,
      env: { ...process.env, ...options?.envVars },
      timeout: (options?.timeout ?? 30) * 1000,
      maxBuffer: 3 * 1024 * 1024,
    });
    return { stdout, stderr, exitCode: 0, success: true };
  },
};

describe("applyPatch tool — preflight", () => {
  it("applies a multi-hunk patch to disk", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-"));
    writeFileSync(
      join(root, "file.ts"),
      "const a = 1;\nconst b = 2;\nconst c = 3;\n",
    );

    const result = await run(
      makeCtx(root),
      `--- a/file.ts
+++ b/file.ts
@@ -1,3 +1,3 @@
-const a = 1;
+const a = 10;
 const b = 2;
-const c = 3;
+const c = 30;
`,
    );

    expect(result.success).toBe(true);
    expect(result.files[0]).toMatchObject({
      path: "file.ts",
      status: "applied",
      hunksApplied: 1,
    });
    expect(readFileSync(join(root, "file.ts"), "utf-8")).toBe(
      "const a = 10;\nconst b = 2;\nconst c = 30;\n",
    );
  });

  it("mutates nothing when any file fails preflight", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-pre-"));
    writeFileSync(join(root, "good.ts"), "one\ntwo\n");
    writeFileSync(join(root, "bad.ts"), "hello\n");

    const result = await run(
      makeCtx(root),
      `--- a/good.ts
+++ b/good.ts
@@ -1,2 +1,2 @@
 one
-two
+TWO
--- a/bad.ts
+++ b/bad.ts
@@ -1 +1 @@
-goodbye
+hi
`,
    );

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Failed applying patch to bad\.ts/);
    expect(result.files[0]).toMatchObject({
      path: "good.ts",
      status: "unapplied",
    });
    expect(result.files[1]).toMatchObject({ path: "bad.ts", status: "failed" });
    expect(readFileSync(join(root, "good.ts"), "utf-8")).toBe("one\ntwo\n");
    expect(readFileSync(join(root, "bad.ts"), "utf-8")).toBe("hello\n");
  });

  it("reports a parse failure without touching anything", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-parse-"));
    writeFileSync(join(root, "file.ts"), "hello\n");

    const result = await run(makeCtx(root), "not a patch");

    expect(result.success).toBe(false);
    expect(result.files).toEqual([]);
    expect(readFileSync(join(root, "file.ts"), "utf-8")).toBe("hello\n");
  });

  it("rejects a patch that targets the same file twice", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-dup-"));
    writeFileSync(join(root, "file.ts"), "a\nb\n");

    const result = await run(
      makeCtx(root),
      `--- a/file.ts
+++ b/file.ts
@@ -1 +1 @@
-a
+A
--- a/file.ts
+++ b/file.ts
@@ -2 +2 @@
-b
+B
`,
    );

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/same file twice/);
    expect(result.files.every((f) => f.status !== "applied")).toBe(true);
    expect(readFileSync(join(root, "file.ts"), "utf-8")).toBe("a\nb\n");
  });

  it("rejects paths escaping the agent working directory", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-escape-"));
    writeFileSync(join(root, "secret.ts"), "keep\n");

    const result = await run(
      makeCtx(root),
      `--- /etc/passwd
+++ /etc/passwd
@@ -1 +1 @@
-x
+y
`,
    );

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/esca/i);
  });

  it("rejects relative paths escaping the agent working directory", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-esc2-"));
    writeFileSync(join(root, "inside.ts"), "a\n");
    writeFileSync(join(root, "outside.ts"), "keep\n");

    const result = await run(
      makeCtx(root),
      `--- a/../outside.ts
+++ b/../outside.ts
@@ -1 +1 @@
-keep
+changed
`,
    );

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/escapes/i);
    expect(readFileSync(join(root, "outside.ts"), "utf-8")).toBe("keep\n");
  });

  it("rejects paths escaping the file workspace root when scoped", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-scope-"));
    const workspace = join(root, "helpers");
    mkdirSync(workspace);
    writeFileSync(join(root, "outside.ts"), "keep\n");

    const result = await run(
      makeCtx(root, { fileWorkspaceRoot: workspace }),
      `--- a/../outside.ts
+++ b/../outside.ts
@@ -1 +1 @@
-keep
+changed
`,
    );

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/escapes/i);
    expect(readFileSync(join(root, "outside.ts"), "utf-8")).toBe("keep\n");
  });
});

describe("applyPatch tool — create and delete", () => {
  it("creates a file via /dev/null and refuses to create it twice", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-new-"));

    const createPatch = `--- /dev/null
+++ b/created.ts
@@ -0,0 +1,2 @@
+one
+two
`;
    const first = await run(makeCtx(root), createPatch);
    expect(first.success).toBe(true);
    expect(first.files[0]).toMatchObject({
      status: "applied",
      created: true,
      hunksApplied: 1,
    });
    expect(readFileSync(join(root, "created.ts"), "utf-8")).toBe("one\ntwo\n");

    const second = await run(makeCtx(root), createPatch);
    expect(second.success).toBe(false);
    expect(second.error).toMatch(/already exists/i);
    expect(readFileSync(join(root, "created.ts"), "utf-8")).toBe("one\ntwo\n");
  });

  it("commits nothing when a later create target already exists", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-coll-"));
    writeFileSync(join(root, "first.ts"), "one\ntwo\n");
    writeFileSync(join(root, "exists.ts"), "already\n");

    const result = await run(
      makeCtx(root),
      `--- a/first.ts
+++ b/first.ts
@@ -1,2 +1,2 @@
 one
-two
+TWO
--- /dev/null
+++ b/exists.ts
@@ -0,0 +1,1 @@
+new content
`,
    );

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/already exists/i);
    expect(result.files[0]).toMatchObject({
      path: "first.ts",
      status: "unapplied",
    });
    expect(result.files[1]).toMatchObject({
      path: "exists.ts",
      status: "failed",
    });
    expect(readFileSync(join(root, "first.ts"), "utf-8")).toBe("one\ntwo\n");
    expect(readFileSync(join(root, "exists.ts"), "utf-8")).toBe("already\n");
  });

  it("validates prepared output against the size limit before any commit", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-size-"));
    writeFileSync(join(root, "first.ts"), "one\ntwo\n");
    writeFileSync(join(root, "big.ts"), "small\n");
    const huge = "x".repeat(1024 * 1024 + 10);

    const result = await run(
      makeCtx(root),
      `--- a/first.ts
+++ b/first.ts
@@ -1,2 +1,2 @@
 one
-two
+TWO
--- a/big.ts
+++ b/big.ts
@@ -1 +1,2 @@
 small
+${huge}
`,
    );

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Text mutation limit/i);
    expect(result.files[0]).toMatchObject({ status: "unapplied" });
    expect(result.files[1]).toMatchObject({ status: "failed" });
    expect(readFileSync(join(root, "first.ts"), "utf-8")).toBe("one\ntwo\n");
    expect(readFileSync(join(root, "big.ts"), "utf-8")).toBe("small\n");
  });

  it("rejects patch output containing NUL bytes before committing", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-nul-"));
    writeFileSync(join(root, "nul.ts"), "a\n");

    const result = await run(
      makeCtx(root),
      `--- a/nul.ts
+++ b/nul.ts
@@ -1 +1 @@
-a
+b${"\0"}c
`,
    );

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/binary/i);
    expect(result.files[0].status).toBe("failed");
    expect(readFileSync(join(root, "nul.ts"), "utf-8")).toBe("a\n");
  });

  it("deletes a file via /dev/null and reports missing targets", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-del-"));
    writeFileSync(join(root, "gone.ts"), "only\n");

    const deleted = await run(
      makeCtx(root),
      `--- a/gone.ts
+++ /dev/null
@@ -1 +0,0 @@
-only
`,
    );
    expect(deleted.success).toBe(true);
    expect(deleted.files[0]).toMatchObject({
      status: "applied",
      deleted: true,
    });

    const missing = await run(
      makeCtx(root),
      `--- a/gone.ts
+++ /dev/null
@@ -1 +0,0 @@
-only
`,
    );
    expect(missing.success).toBe(false);
    expect(missing.files[0].status).toBe("failed");
  });
});

describe("applyPatch tool — formatting on disk", () => {
  it("preserves a missing final newline when the hunk stays off EOF", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-nl-"));
    writeFileSync(join(root, "file.ts"), "a\nb\nc");

    const result = await run(
      makeCtx(root),
      `--- a/file.ts
+++ b/file.ts
@@ -1 +1 @@
-a
+A
`,
    );

    expect(result.success).toBe(true);
    expect(readFileSync(join(root, "file.ts"), "utf-8")).toBe("A\nb\nc");
  });

  it("adapts an LF patch to a CRLF file and reports it", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-crlf-"));
    writeFileSync(join(root, "file.ts"), "one\r\ntwo\r\nthree\r\n");

    const result = await run(
      makeCtx(root),
      `--- a/file.ts
+++ b/file.ts
@@ -1,3 +1,3 @@
 one
-two
+TWO
 three
`,
    );

    expect(result.success).toBe(true);
    expect(result.files[0].eolAdaptation).toBe("added-cr");
    expect(readFileSync(join(root, "file.ts"), "utf-8")).toBe(
      "one\r\nTWO\r\nthree\r\n",
    );
  });

  it("preserves a BOM across an edit", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-bom-"));
    writeFileSync(join(root, "file.ts"), "﻿first\nsecond\n");

    const result = await run(
      makeCtx(root),
      `--- a/file.ts
+++ b/file.ts
@@ -1 +1 @@
-first
+FIRST
`,
    );

    expect(result.success).toBe(true);
    expect(readFileSync(join(root, "file.ts"), "utf-8")).toBe(
      "﻿FIRST\nsecond\n",
    );
  });
});

describe("applyPatch tool — interruption", () => {
  it("marks everything unapplied when aborted before commit", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-abort-"));
    writeFileSync(join(root, "file.ts"), "a\nb\n");
    const controller = new AbortController();
    controller.abort();

    const result = await run(
      makeCtx(root, { abortSignal: controller.signal }),
      `--- a/file.ts
+++ b/file.ts
@@ -1,2 +1,2 @@
-a
+A
 b
`,
    );

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/abort/i);
    expect(result.files.every((f) => f.status === "unapplied")).toBe(true);
    expect(readFileSync(join(root, "file.ts"), "utf-8")).toBe("a\nb\n");
  });
});

describe("duplicateTargetKey", () => {
  const neverRuns = async () => ({
    stdout: "",
    stderr: "",
    exitCode: 0,
    success: true,
  });

  it("folds case for windows sandboxes", () => {
    const ctx = makeCtx("/w", {
      sandbox: { type: "windows", execute: neverRuns },
    });
    expect(duplicateTargetKey(ctx, "/w/A.ts")).toBe("/w/a.ts");
  });

  it("preserves case for linux sandboxes", () => {
    const ctx = makeCtx("/w", {
      sandbox: { type: "linux", execute: neverRuns },
    });
    expect(duplicateTargetKey(ctx, "/w/A.ts")).toBe("/w/A.ts");
  });

  it("follows host platform semantics without a sandbox", () => {
    const ctx = makeCtx("/w");
    const expected = process.platform === "win32" ? "/w/a.ts" : "/w/A.ts";
    expect(duplicateTargetKey(ctx, "/w/A.ts")).toBe(expected);
  });
});

describe("applyPatch tool — sandbox routing", () => {
  it("applies through the remote file operation path", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-patch-sbx-"));
    const workspace = join(root, "helpers");
    mkdirSync(workspace);
    writeFileSync(join(workspace, "file.ts"), "one\ntwo\nthree\n");

    const result = await run(
      makeCtx(root, {
        fileWorkspaceRoot: workspace,
        sandbox: linuxSandbox,
      }),
      `--- a/file.ts
+++ b/file.ts
@@ -1,3 +1,3 @@
 one
-two
+TWO
 three
`,
    );

    expect(result.success).toBe(true);
    expect(result.files[0]).toMatchObject({
      status: "applied",
      hunksApplied: 1,
    });
    expect(readFileSync(join(workspace, "file.ts"), "utf-8")).toBe(
      "one\nTWO\nthree\n",
    );
  });
});
