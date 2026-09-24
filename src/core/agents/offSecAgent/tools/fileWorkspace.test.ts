import { execFile } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import {
  deleteWorkspaceFile,
  readWorkspaceFile,
  resolveFilePath,
  withWorkspaceFileLock,
  writeWorkspaceFile,
} from "./fileWorkspace";
import type { UnifiedSandbox } from "./sandbox";
import type { ToolContext } from "./types";

const execute = promisify(execFile);
const roots: string[] = [];
const linux: UnifiedSandbox = {
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

const windows: UnifiedSandbox = {
  type: "windows",
  async execute(command, options) {
    const { stdout, stderr } = await execute(
      "cmd.exe",
      ["/d", "/s", "/c", command],
      {
        cwd: options?.cwd,
        env: { ...process.env, ...options?.envVars },
        timeout: (options?.timeout ?? 30) * 1000,
        maxBuffer: 3 * 1024 * 1024,
      },
    );
    return { stdout, stderr, exitCode: 0, success: true };
  },
};

afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

async function fixture(sandbox?: UnifiedSandbox) {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "apex-file-workspace-")),
  );
  roots.push(root);
  const workspace = join(root, "helpers");
  await mkdir(workspace);
  const ctx = {
    agentCwd: root,
    fileWorkspaceRoot: workspace,
    sandbox,
  } as ToolContext;
  return { root, workspace, ctx };
}

describe.each([
  { name: "local", sandbox: undefined },
  ...(process.platform === "win32"
    ? [{ name: "Windows process adapter", sandbox: windows }]
    : [{ name: "Linux process adapter", sandbox: linux }]),
])("file workspace: $name", ({ sandbox }) => {
  it("resolves relative paths in the file workspace, preserves bytes, and checks stale edits", async () => {
    const { ctx, workspace } = await fixture(sandbox);
    const file = await resolveFilePath(ctx, "nested/helper's café.txt");
    expect(file).toBe(join(workspace, "nested/helper's café.txt"));
    await writeWorkspaceFile(ctx, file, "\uFEFFold\r\n", { expected: null });
    expect(await readWorkspaceFile(ctx, file)).toBe("\uFEFFold\r\n");
    await expect(
      writeWorkspaceFile(ctx, file, "clobber", { expected: "old\n" }),
    ).rejects.toThrow(/changed/i);
    expect(await readFile(file, "utf8")).toBe("\uFEFFold\r\n");
    await writeWorkspaceFile(ctx, file, "\uFEFFnew\r\n", {
      expected: "\uFEFFold\r\n",
    });
    await expect(
      deleteWorkspaceFile(ctx, file, { expected: "stale" }),
    ).rejects.toThrow(/changed/i);
    await deleteWorkspaceFile(ctx, file, { expected: "\uFEFFnew\r\n" });
    await expect(readFile(file)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("admits one exclusive creator and preserves the winner", async () => {
    const { ctx } = await fixture(sandbox);
    const file = await resolveFilePath(ctx, "new.txt");
    const outcomes = await Promise.allSettled(
      ["first", "second"].map((content) =>
        writeWorkspaceFile(ctx, file, content, { expected: null }),
      ),
    );
    expect(outcomes.filter((x) => x.status === "fulfilled")).toHaveLength(1);
    expect(await readFile(file, "utf8")).toBe(
      outcomes[0].status === "fulfilled" ? "first" : "second",
    );
  });

  it("refuses traversal and an existing symlink to an outside directory", async () => {
    const { root, workspace, ctx } = await fixture(sandbox);
    const outside = join(root, "target");
    await mkdir(outside);
    await writeFile(join(outside, "source.txt"), "source");
    await symlink(
      outside,
      join(workspace, "escape"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(resolveFilePath(ctx, "../target/source.txt")).rejects.toThrow(
      /escapes|reparse/i,
    );
    await expect(resolveFilePath(ctx, "escape/source.txt")).rejects.toThrow(
      /escapes|reparse/i,
    );
    await expect(resolveFilePath(ctx, "escape/new.txt")).rejects.toThrow(
      /escapes|reparse/i,
    );
    await expect(
      readWorkspaceFile(ctx, join(outside, "source.txt")),
    ).rejects.toThrow(/escapes|reparse/i);
    await expect(
      writeWorkspaceFile(ctx, join(outside, "new.txt"), "wrong"),
    ).rejects.toThrow(/escapes|reparse/i);
    expect(await resolveFilePath(ctx, "..cache/new.txt")).toBe(
      join(workspace, "..cache/new.txt"),
    );
  });

  it("bounds reads and refuses binary, invalid UTF-8, and directories", async () => {
    const { workspace, ctx } = await fixture(sandbox);
    for (const [name, content] of [
      ["large", Buffer.alloc(1024 * 1024 + 1, 97)],
      ["binary", Buffer.from([0, 1])],
      ["invalid", Buffer.from([0xff])],
    ] as const) {
      const file = join(workspace, name);
      await writeFile(file, content);
      await expect(readWorkspaceFile(ctx, file)).rejects.toThrow();
    }
    await expect(readWorkspaceFile(ctx, workspace)).rejects.toThrow(
      /ordinary|directory/i,
    );
  });

  it.skipIf(process.platform === "win32")(
    "preserves executable permissions on replacement",
    async () => {
      const { ctx } = await fixture(sandbox);
      const file = await resolveFilePath(ctx, "helper.sh");
      await writeFile(file, "old");
      await chmod(file, 0o751);
      await writeWorkspaceFile(ctx, file, "new", { expected: "old" });
      expect((await stat(file)).mode & 0o777).toBe(0o751);
    },
  );

  it("does not interpolate shell syntax in paths or contents", async () => {
    const { ctx, workspace } = await fixture(sandbox);
    const file = await resolveFilePath(ctx, "$(touch injected)' helper.txt");
    await writeWorkspaceFile(ctx, file, "$HOME `id` ' literal", {
      expected: null,
    });
    expect(await readWorkspaceFile(ctx, file)).toBe("$HOME `id` ' literal");
    await expect(stat(join(workspace, "injected"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });
});

it("releases failed locks and rejects cancelled queued operations", async () => {
  const { ctx } = await fixture();
  const file = await resolveFilePath(ctx, "file.txt");
  await expect(
    withWorkspaceFileLock(ctx, file, async () => {
      throw new Error("operation failed");
    }),
  ).rejects.toThrow("operation failed");
  await expect(
    withWorkspaceFileLock(ctx, file, async () => "next"),
  ).resolves.toBe("next");
  ctx.abortSignal = AbortSignal.abort();
  await expect(writeWorkspaceFile(ctx, file, "cancelled")).rejects.toThrow();
  await expect(stat(file)).rejects.toMatchObject({ code: "ENOENT" });
});

it("does not read or write a host decoy after a sandbox failure", async () => {
  const { workspace, ctx } = await fixture({
    type: "linux",
    execute: async () => {
      throw new Error("remote offline");
    },
  });
  const file = join(workspace, "decoy.txt");
  await writeFile(file, "host decoy");
  await expect(readWorkspaceFile(ctx, file)).rejects.toThrow("remote offline");
  await expect(
    writeWorkspaceFile(ctx, file, "remote contents"),
  ).rejects.toThrow("remote offline");
  expect(await readFile(file, "utf8")).toBe("host decoy");
});
