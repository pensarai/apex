import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PerCommandShell } from "../../agents/offSecAgent/tools/perCommandShell";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import { collectCommand } from "./collectCommand";
import { LocalBackends } from "./local";
import {
  appendArtifactSummary,
  resolveArtifactFs,
  resolveBackends,
  resolveScriptRunner,
} from "./resolve";
import type { CommandBackend } from "./types";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});
async function context() {
  const root = await mkdtemp(join(tmpdir(), "apex-capability-"));
  roots.push(root);
  return {
    agentCwd: root,
    fileWorkspaceRoot: join(root, "workspace"),
    session: { rootPath: join(root, "session") },
  } as ToolContext;
}

describe("artifact capability", () => {
  it("allows host session artifacts beyond the text-tool cap without widening workspace tools", async () => {
    const ctx = await context();
    const artifact = join(ctx.session.rootPath, "pocs", "capture.json");
    const content = "x".repeat(1024 * 1024 + 1);
    expect(
      (
        await resolveBackends(ctx).fs.write(artifact, content, {
          mode: "overwrite",
        })
      ).success,
    ).toBe(false);
    expect(
      (
        await resolveArtifactFs(ctx).write(artifact, content, {
          mode: "overwrite",
        })
      ).success,
    ).toBe(true);
    expect(await readFile(artifact, "utf8")).toBe(content);
    const script = join(ctx.session.rootPath, "pocs", "proof.sh");
    expect(
      (
        await resolveArtifactFs(ctx).write(script, "echo proof", {
          mode: "overwrite",
          permissions: 0o755,
        })
      ).success,
    ).toBe(true);
    if (process.platform !== "win32")
      expect((await stat(script)).mode & 0o777).toBe(0o755);
    expect(
      (
        await resolveArtifactFs(ctx).write(join(ctx.agentCwd, "escape"), "x", {
          mode: "overwrite",
        })
      ).success,
    ).toBe(false);
  });

  it("keeps injected storage authoritative when it fails", async () => {
    const ctx = await context();
    const write = vi.fn().mockResolvedValue({
      success: false,
      error: "remote storage failed",
      path: "/remote",
    });
    const backend = LocalBackends(ctx);
    ctx.backends = {
      ...backend,
      sandboxed: true,
      fs: { ...backend.fs, write },
    };
    const artifact = join(ctx.session.rootPath, "finding.json");
    expect(
      await resolveArtifactFs(ctx).write(artifact, "data", {
        mode: "overwrite",
      }),
    ).toMatchObject({ success: false, error: "remote storage failed" });
    expect(write).toHaveBeenCalledOnce();
    await expect(readFile(artifact)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("does not dispatch a command to a configured sandbox after cancellation", async () => {
    const ctx = await context();
    const execute = vi.fn();
    ctx.sandbox = { type: "linux", execute };
    ctx.abortSignal = AbortSignal.abort();
    const events = [];
    for await (const event of resolveBackends(ctx).command.run("echo remote"))
      events.push(event);
    expect(events).toContainEqual({
      type: "end",
      exitCode: 130,
      timedOut: false,
    });
    expect(execute).not.toHaveBeenCalled();
  });
});

describe("artifact summary append", () => {
  it("preserves every entry across separate processes", async () => {
    const ctx = await context();
    const path = join(ctx.session.rootPath, "findings-summary.md");
    const modulePath = new URL(
      "../../agents/offSecAgent/tools/fileWorkspace.ts",
      import.meta.url,
    ).href;
    await Promise.all(
      Array.from({ length: 4 }, (_, worker) => {
        const program = `import { appendLocalWorkspaceFile } from ${JSON.stringify(modulePath)};
        const ctx = ${JSON.stringify({ agentCwd: ctx.session.rootPath, fileWorkspaceRoot: ctx.session.rootPath })};
        for (let i = 0; i < 12; i++) await appendLocalWorkspaceFile(ctx, ${JSON.stringify(path)}, "HEADER\\n", "worker-${worker}-" + i + "\\n");`;
        return promisify(execFile)("bun", ["--no-env-file", "-e", program]);
      }),
    );
    const entries = (await readFile(path, "utf8")).trim().split("\n");
    expect(entries.filter((line) => line === "HEADER")).toHaveLength(1);
    for (let worker = 0; worker < 4; worker++) {
      for (let i = 0; i < 12; i++)
        expect(
          entries.filter((line) => line === `worker-${worker}-${i}`),
        ).toHaveLength(1);
    }
  });

  it("retains the injected readRaw then write invocation trace", async () => {
    const ctx = await context();
    const trace: unknown[] = [];
    const path = "/durable/findings-summary.md";
    ctx.backends = {
      fs: {
        readRaw: async (file: string) => {
          trace.push(["readRaw", file]);
          return { success: true, content: "existing\n" };
        },
        write: async (file: string, content: string, options: unknown) => {
          trace.push(["write", file, content, options]);
          return { success: true, error: "", path: file };
        },
      },
    } as ToolContext["backends"];
    await appendArtifactSummary(ctx, path, "header\n", "new entry\n");
    expect(trace).toEqual([
      ["readRaw", path],
      ["write", path, "existing\nnew entry\n", { mode: "overwrite" }],
    ]);
    await expect(
      readFile(join(ctx.session.rootPath, "findings-summary.md")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });
});

describe("script transport resolution", () => {
  it("executes a native script path without shell interpretation", async () => {
    const ctx = await context();
    const path = join(ctx.agentCwd, "proof ' $HOME & %.js");
    await writeFile(path, "console.log(process.argv[1])");
    const result = await collectCommand(
      resolveScriptRunner(ctx)(process.execPath, path, { timeoutSeconds: 10 }),
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe(path);
  });

  it("preserves exact injected command bytes and options on a Windows host", async () => {
    const ctx = await context();
    const run = vi.fn<CommandBackend["run"]>(async function* () {
      yield { type: "end" as const, exitCode: 0, timedOut: false };
    });
    ctx.backends = { ...LocalBackends(ctx), command: { run } };
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    if (!platform) throw new Error("Missing process.platform descriptor");
    Object.defineProperty(process, "platform", { value: "win32" });
    const options = {
      timeoutSeconds: 37,
      abortSignal: new AbortController().signal,
    };
    try {
      await collectCommand(
        resolveScriptRunner(ctx)("node", "/remote/Ada's proof & $.js", options),
      );
      expect(run.mock.calls).toEqual([
        ["node '/remote/Ada'\\''s proof & $.js'", options],
      ]);
      expect(run.mock.calls[0]?.[1]).toBe(options);
    } finally {
      Object.defineProperty(process, "platform", platform);
    }
  });

  it("does not fall back to native execution after an injected failure", async () => {
    const ctx = await context();
    const native = vi.spyOn(PerCommandShell.prototype, "executeArgv");
    const run = vi.fn<CommandBackend["run"]>(async function* () {
      yield { type: "start" };
      throw new Error("injected execution failed");
    });
    ctx.backends = { ...LocalBackends(ctx), command: { run } };
    await expect(
      collectCommand(resolveScriptRunner(ctx)("node", "missing.js")),
    ).rejects.toThrow("injected execution failed");
    expect(run).toHaveBeenCalledOnce();
    expect(native).not.toHaveBeenCalled();
    native.mockRestore();
  });

  it("preserves the configured sandbox command string and deadline", async () => {
    const ctx = await context();
    const execute = vi
      .fn()
      .mockResolvedValue({ stdout: "remote", stderr: "", exitCode: 0 });
    ctx.sandbox = { type: "linux", execute };
    const result = await collectCommand(
      resolveScriptRunner(ctx)("node", "/remote/Ada's proof & $.js", {
        timeoutSeconds: 37,
      }),
    );
    expect(execute).toHaveBeenCalledOnce();
    expect(execute).toHaveBeenCalledWith(
      "node '/remote/Ada'\\''s proof & $.js'",
      expect.objectContaining({ timeout: 37, cwd: ctx.agentCwd }),
    );
    expect(result.stdout).toBe("remote");
  });
});
