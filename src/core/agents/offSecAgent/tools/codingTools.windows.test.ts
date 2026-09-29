import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile as readDisk,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { winScriptFromEnv } from "./__tests__/sandboxScript";
import { applyPatch } from "./applyPatch";
import { createFile } from "./createFile";
import { deleteFile } from "./deleteFile";
import { type GlobResult, globFiles } from "./glob";
import { type GrepResult, grep } from "./grep";
import { type ListFilesResult, listFiles } from "./listFiles";
import { readFile } from "./readFile";
import type { UnifiedSandbox } from "./sandbox";
import { winScriptEnv } from "./sandboxScript";
import type { ToolContext } from "./types";
import { updateFile } from "./updateFile";

const roots: string[] = [];
const callOptions = { toolCallId: "windows-file-contract", messages: [] };
const toolCallDescription = "Exercise native Windows file operations";

const sandbox: UnifiedSandbox = {
  type: "windows",
  execute(command, opts) {
    return new Promise((resolve) => {
      execFile(
        "cmd.exe",
        ["/d", "/s", "/c", command],
        {
          cwd: opts?.cwd,
          env: { ...process.env, ...opts?.envVars },
          timeout: (opts?.timeout ?? 30) * 1_000,
          maxBuffer: 4 * 1024 * 1024,
          encoding: "utf8",
        },
        (error, stdout, stderr) => {
          const exitCode = error
            ? typeof error.code === "number"
              ? error.code
              : 1
            : 0;
          resolve({ stdout, stderr, exitCode, success: exitCode === 0 });
        },
      );
    });
  },
};

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "apex coding tools "));
  roots.push(root);
  const workspace = join(root, "helpers");
  await mkdir(workspace);
  const ctx = {
    agentCwd: root,
    fileWorkspaceRoot: workspace,
    sandbox,
    session: { id: "windows-coding-tools", rootPath: root },
  } as ToolContext;
  return { root, workspace, ctx };
}

afterEach(async () => {
  for (const root of roots.splice(0)) {
    await rm(root, { recursive: true, force: true });
  }
});

describe.skipIf(process.platform !== "win32")(
  "Windows coding tool runtime",
  () => {
    it("marks completed grep output above the response limit as truncated", async () => {
      const { workspace, ctx } = await fixture();
      await writeFile(
        join(workspace, "overflow.txt"),
        `needle${"x".repeat(52_000)}\n`,
      );
      const result = (await grep(ctx).execute?.(
        { pattern: "needle", toolCallDescription },
        callOptions,
      )) as GrepResult;
      expect(result.success).toBe(false);
      expect(result.truncated).toBe(true);
      expect(result.matchCount).toBeUndefined();
      expect(result.output).toContain("truncated at");
      expect(result.output.length).toBeLessThan(50_200);
    });

    it("rejects non-directory glob roots and accepts an empty directory", async () => {
      const { workspace, ctx } = await fixture();
      await writeFile(join(workspace, "file.txt"), "source");
      await mkdir(join(workspace, "empty"));
      for (const runtimeCtx of [ctx, { ...ctx, sandbox: undefined }]) {
        for (const path of ["file.txt", "missing"]) {
          const result = (await globFiles(runtimeCtx).execute?.(
            { pattern: "**/*", path, toolCallDescription },
            callOptions,
          )) as GlobResult;
          expect(result.success).toBe(false);
          expect(result.error).toMatch(/not a directory|ENOENT/i);
          expect(result.files).toEqual([]);
        }
        expect(
          await globFiles(runtimeCtx).execute?.(
            { pattern: "**/*", path: "empty", toolCallDescription },
            callOptions,
          ),
        ).toMatchObject({ success: true, error: "", files: [], count: 0 });
      }
    });

    it("searches UTF-8 file bodies with non-ASCII patterns", async () => {
      const { workspace, ctx } = await fixture();
      await writeFile(join(workspace, "unicode.txt"), "café 東京 🔐\n");
      for (const pattern of ["café", "東京", "🔐"]) {
        const result = (await grep(ctx).execute?.(
          { pattern, flags: "-nF", toolCallDescription },
          callOptions,
        )) as GrepResult;
        expect(result).toMatchObject({ success: true, matchCount: 1 });
        expect(result.output).toContain(":1:café 東京 🔐");
      }
    }, 60_000);

    it("does not descend directory junctions in the local runtime", async () => {
      const { root, workspace, ctx } = await fixture();
      const outside = join(root, "outside");
      await mkdir(outside);
      await writeFile(join(outside, "secret.txt"), "outside source\n");
      await writeFile(join(workspace, "inside.txt"), "helper\n");
      await symlink(outside, join(workspace, "escape"), "junction");
      await symlink(workspace, join(workspace, "cycle"), "junction");
      expect(
        await globFiles({ ...ctx, sandbox: undefined }).execute?.(
          { pattern: "**/*.txt", toolCallDescription },
          callOptions,
        ),
      ).toMatchObject({ success: true, files: ["inside.txt"] });
    });

    it("matches glob path segments without letting stars cross directories", async () => {
      const { workspace, ctx } = await fixture();
      await mkdir(join(workspace, "src", "nested"), { recursive: true });
      await mkdir(join(workspace, ".config"));
      await writeFile(join(workspace, ".config", "settings.ts"), "config\n");
      for (const dir of [".🔐", ".["]) {
        await mkdir(join(workspace, dir));
        await writeFile(join(workspace, dir, "settings.ts"), "config\n");
      }
      for (const name of ["root.ts", "src/a.ts", "src/nested/b.ts"]) {
        await writeFile(join(workspace, name), "source\n");
      }
      for (const [pattern, files] of [
        ["*.ts", ["root.ts"]],
        ["src/*.ts", ["src/a.ts"]],
        ["**/*.ts", ["root.ts", "src/a.ts", "src/nested/b.ts"]],
        ["{src,.config}/*.ts", [".config/settings.ts", "src/a.ts"]],
        [".??/*.ts", [".🔐/settings.ts"]],
        [".[!]/*.ts", [".[/settings.ts"]],
        [".[[a]/*.ts", [".[/settings.ts"]],
        [".[]/*.ts", []],
      ] as const) {
        expect(
          await globFiles(ctx).execute?.(
            { pattern, toolCallDescription },
            callOptions,
          ),
        ).toMatchObject({ success: true, files });
      }
    }, 60_000);

    it("prunes hidden directories unrelated to explicitly hidden glob patterns", async () => {
      const { workspace, ctx } = await fixture();
      for (const dir of [".cache", ".config", "src/.config", ".env"]) {
        await mkdir(join(workspace, dir), { recursive: true });
      }
      await writeFile(join(workspace, ".config", "settings.ts"), "config");
      await writeFile(join(workspace, "src", "visible.ts"), "source");
      await writeFile(join(workspace, "src", ".env"), "config");
      const measuredSandbox: UnifiedSandbox = {
        ...sandbox,
        execute(command, options) {
          if (options?.envVars?.APEX_GLOB_PATH !== undefined) {
            const script = winScriptFromEnv(options.envVars);
            const visit = "$d=$stack.Pop()";
            expect(script).toContain(visit);
            const measured = script.replace(
              visit,
              `${visit}\nif($d.EndsWith('\\.cache') -or $d.EndsWith('\\.env') -or $d.EndsWith('\\src\\.config')){throw 'Glob entered an unrelated hidden directory'}`,
            );
            return sandbox.execute(command, {
              ...options,
              envVars: { ...options.envVars, ...winScriptEnv(measured) },
            });
          }
          return sandbox.execute(command, options);
        },
      };
      for (const [pattern, files] of [
        ["**/.env", ["src/.env"]],
        ["{src,.config}/*.ts", [".config/settings.ts", "src/visible.ts"]],
      ] as const) {
        expect(
          await globFiles({ ...ctx, sandbox: measuredSandbox }).execute?.(
            { pattern, toolCallDescription },
            callOptions,
          ),
        ).toMatchObject({ success: true, error: "", files });
      }
    }, 60_000);

    it("rejects listing a regular file but accepts an empty directory", async () => {
      const { workspace, ctx } = await fixture();
      await writeFile(join(workspace, "file.txt"), "content\n");
      await mkdir(join(workspace, "empty"));
      for (const recursive of [false, true]) {
        const result = (await listFiles(ctx).execute?.(
          { directory: "file.txt", recursive, toolCallDescription },
          callOptions,
        )) as ListFilesResult;
        expect(result.success).toBe(false);
        expect(result.error).toContain("not a directory");
        expect(
          await listFiles(ctx).execute?.(
            { directory: "empty", recursive, toolCallDescription },
            callOptions,
          ),
        ).toMatchObject({ success: true, files: [], count: 0 });
      }
    }, 60_000);

    it("stops line-window reads before scanning the remaining bytes", async () => {
      const { workspace, ctx } = await fixture();
      await writeFile(
        join(workspace, "large.txt"),
        `first\nsecond\n${"tail\n".repeat(100_000)}`,
      );
      const boundedSandbox: UnifiedSandbox = {
        ...sandbox,
        execute(command, options) {
          if (options?.envVars?.APEX_READ_START !== undefined) {
            const script = winScriptFromEnv(options.envVars);
            const read = "$n=$fs.Read($buf,0,65536)";
            expect(script).toContain(read);
            const measured = script.replace(
              read,
              `${read}; if($fs.Position -gt 131072){throw 'Line window scanned the file tail'}`,
            );
            return sandbox.execute(command, {
              ...options,
              envVars: { ...options.envVars, ...winScriptEnv(measured) },
            });
          }
          return sandbox.execute(command, options);
        },
      };
      expect(
        await readFile({ ...ctx, sandbox: boundedSandbox }).execute?.(
          { path: "large.txt", startLine: 1, endLine: 2, toolCallDescription },
          callOptions,
        ),
      ).toMatchObject({
        success: true,
        content: "     1|first\n     2|second",
        stoppedAtLine: 3,
      });
    }, 60_000);

    it("searches nested files, reports no-match and capped results, and skips junctions", async () => {
      const { root, workspace, ctx } = await fixture();
      await mkdir(join(workspace, "nested"));
      await writeFile(join(workspace, "nested", "café.txt"), "inside marker\n");
      await mkdir(join(workspace, "node_modules"));
      await writeFile(
        join(workspace, "node_modules", "ignored.txt"),
        "dependency\n",
      );
      const outside = join(root, "outside");
      await mkdir(outside);
      await writeFile(join(outside, "secret.txt"), "outside marker\n");
      await symlink(outside, join(workspace, "escape"), "junction");

      const listed = (await listFiles(ctx).execute?.(
        { recursive: true, toolCallDescription },
        callOptions,
      )) as ListFilesResult;
      expect(listed).toMatchObject({ success: true });
      expect(listed?.files.map((path) => path.replaceAll("\\", "/"))).toContain(
        "nested/café.txt",
      );
      expect(listed?.files.join("\n")).not.toContain("secret.txt");
      const matched = (await globFiles(ctx).execute?.(
        { pattern: "**/*.txt", toolCallDescription },
        callOptions,
      )) as GlobResult;
      expect(matched).toMatchObject({ success: true });
      expect(
        matched?.files.map((path) => path.replaceAll("\\", "/")),
      ).toContain("nested/café.txt");
      expect(matched?.files.join("\n")).not.toContain("secret.txt");
      expect(matched?.files.join("\n")).not.toContain("ignored.txt");
      const found = (await grep(ctx).execute?.(
        { pattern: "marker", toolCallDescription },
        callOptions,
      )) as GrepResult;
      expect(found).toMatchObject({ success: true, matchCount: 1 });
      expect(found?.output).toContain("inside marker");
      expect(found?.output).not.toContain("outside marker");
      const clustered = (await grep(ctx).execute?.(
        { pattern: "INSIDE MARKER", flags: "-rni", toolCallDescription },
        callOptions,
      )) as GrepResult;
      expect(clustered).toMatchObject({ success: true, matchCount: 1 });
      expect(clustered.output).toContain(":1:inside marker");
      const absent = (await grep(ctx).execute?.(
        { pattern: "no-such-text", toolCallDescription },
        callOptions,
      )) as GrepResult;
      expect(absent.error).toBe("");
      expect(absent).toMatchObject({
        success: true,
        matchCount: 0,
        output: "(no matches)",
      });

      await writeFile(
        join(workspace, "many.txt"),
        `${"marker ".repeat(100)}\n${"marker\n".repeat(15_000)}`,
      );
      const filenames = (await grep(ctx).execute?.(
        { pattern: "marker", flags: "-l", toolCallDescription },
        callOptions,
      )) as GrepResult;
      expect(filenames).toMatchObject({ success: true, matchCount: 2 });
      const capped = (await grep(ctx).execute?.(
        { pattern: "marker", toolCallDescription },
        callOptions,
      )) as GrepResult;
      expect(capped).toMatchObject({ success: false, truncated: true });
      expect(capped?.matchCount).toBeUndefined();
      expect(capped?.output.length).toBeLessThanOrEqual(51_000);
    }, 60_000);

    it("creates, reads, edits, patches, and deletes through actual PowerShell", async () => {
      const { workspace, ctx } = await fixture();
      const path = "helper's café.txt";
      const content = "\uFEFFfirst\r\nold\r\nlast\r\n";
      const created = await createFile(ctx).execute?.(
        { path, content, toolCallDescription },
        callOptions,
      );
      expect(created).toMatchObject({ success: true });
      expect(await readDisk(join(workspace, path), "utf8")).toBe(content);
      const collision = await createFile(ctx).execute?.(
        { path, content: "collision", toolCallDescription },
        callOptions,
      );
      expect(collision).toMatchObject({ success: false });
      const edited = await updateFile(ctx).execute?.(
        {
          path,
          oldContent: "first\nold",
          newContent: "first\nnew",
          toolCallDescription,
        },
        callOptions,
      );
      expect(edited).toMatchObject({ success: true });
      expect(await readDisk(join(workspace, path), "utf8")).toBe(
        "\uFEFFfirst\r\nnew\r\nlast\r\n",
      );
      const read = await readFile(ctx).execute?.(
        { path, byteOffset: 3, byteCount: 5, toolCallDescription },
        callOptions,
      );
      expect(read).toMatchObject({
        success: true,
        content: "first",
        stoppedAtByte: 8,
      });
      const patched = await applyPatch(ctx).execute?.(
        {
          patch: `--- a/${path}\n+++ b/${path}\n@@ -2,1 +2,1 @@\n-new\n+patched\n`,
          toolCallDescription,
        },
        callOptions,
      );
      expect(patched).toMatchObject({ success: true });
      expect(await readDisk(join(workspace, path), "utf8")).toBe(
        "\uFEFFfirst\r\npatched\r\nlast\r\n",
      );
      const deleted = await deleteFile(ctx).execute?.(
        { path, toolCallDescription },
        callOptions,
      );
      expect(deleted).toMatchObject({ success: true });
      await expect(readDisk(join(workspace, path))).rejects.toMatchObject({
        code: "ENOENT",
      });
    }, 60_000);

    it("refuses a junction that leads outside the helper workspace", async () => {
      const { root, workspace, ctx } = await fixture();
      const target = join(root, "target-source");
      await mkdir(target);
      await writeFile(join(target, "private.txt"), "target-only source");
      await symlink(target, join(workspace, "escape"), "junction");
      const read = await readFile(ctx).execute?.(
        { path: "escape/private.txt", toolCallDescription },
        callOptions,
      );
      expect(read).toMatchObject({ success: false, content: "" });
      const created = await createFile(ctx).execute?.(
        {
          path: "escape/new.txt",
          content: "wrong destination",
          toolCallDescription,
        },
        callOptions,
      );
      expect(created).toMatchObject({ success: false });
      await expect(readDisk(join(target, "new.txt"))).rejects.toMatchObject({
        code: "ENOENT",
      });
    }, 60_000);
  },
);
