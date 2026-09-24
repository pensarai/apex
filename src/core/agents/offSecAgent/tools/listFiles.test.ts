import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { winScriptFromEnv } from "./__tests__/sandboxScript";
import { type ListFilesResult, listFiles } from "./listFiles";
import type { UnifiedSandbox } from "./sandbox";
import type { ToolContext } from "./types";

function makeCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: ["https://example.com"],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/test",
      logsPath: "/tmp/test/logs",
      findingsPath: "/tmp/test/findings",
      scratchpadPath: "/tmp/test/scratchpad",
      pocsPath: "/tmp/test/pocs",
    } as SessionInfo,
    agentCwd: "/tmp/test",
    target: "https://example.com",
    ...overrides,
  };
}

const scratchDirs: string[] = [];
function scratchDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "apex-listfiles-test-"));
  scratchDirs.push(dir);
  return dir;
}

function realLinuxSandbox(): UnifiedSandbox {
  return {
    type: "linux",
    execute: async (command, opts) => {
      const res = spawnSync("bash", ["-c", command], {
        encoding: "utf8",
        timeout: 35_000,
        env: { ...process.env, ...opts?.envVars },
      });
      return {
        stdout: res.stdout ?? "",
        stderr: res.stderr ?? "",
        exitCode: res.status ?? 1,
        success: res.status === 0,
      };
    },
  };
}

type ListFilesCall = Parameters<
  NonNullable<ReturnType<typeof listFiles>["execute"]>
>[0];

async function runList(
  ctx: ToolContext,
  input: ListFilesCall,
): Promise<ListFilesResult> {
  return (await listFiles(ctx).execute?.(input, {
    toolCallId: "tc_test",
    messages: [],
    abortSignal: ctx.abortSignal,
  })) as ListFilesResult;
}

afterEach(() => {
  for (const dir of scratchDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function seedTree(dir: string) {
  mkdirSync(join(dir, "src"));
  mkdirSync(join(dir, ".hidden"));
  writeFileSync(join(dir, "README.md"), "# readme");
  writeFileSync(join(dir, ".env"), "SECRET=1");
  writeFileSync(join(dir, "src", "a.ts"), "export {}");
  writeFileSync(join(dir, ".hidden", "k.txt"), "k");
}

describe("listFiles local", () => {
  it("lists immediate entries including dotfiles with dir suffixes", async () => {
    const dir = scratchDir();
    seedTree(dir);

    const result = await runList(makeCtx({ agentCwd: dir }), {
      toolCallDescription: "list root",
    });

    expect(result.success).toBe(true);
    expect(result.files).toContain("src/");
    expect(result.files).toContain(".hidden/");
    expect(result.files).toContain("README.md");
    expect(result.files).toContain(".env");
    expect(result.count).toBe(4);
    expect(result.totalFound).toBeUndefined();
  });

  it("lists recursively without descending or suffixing symlinked dirs", async () => {
    const dir = scratchDir();
    seedTree(dir);
    const outside = scratchDir();
    writeFileSync(join(outside, "secret.txt"), "target source");
    symlinkSync(outside, join(dir, "link-out"));

    const result = await runList(makeCtx({ agentCwd: dir }), {
      recursive: true,
      toolCallDescription: "recursive listing",
    });

    expect(result.success).toBe(true);
    // The symlink appears as a plain entry; its target's bytes are not listed.
    expect(result.files).toContain("link-out");
    expect(result.files.some((f) => f.startsWith("link-out/"))).toBe(false);
    expect(result.files).toContain("src/a.ts");
    expect(result.files).toContain(".hidden/k.txt");
  });

  it("fails on a non-directory path", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "file.txt"), "x");

    const result = await runList(makeCtx({ agentCwd: dir }), {
      directory: "file.txt",
      toolCallDescription: "list a file",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("not a directory");
  });

  it("honors fileWorkspaceRoot confinement", async () => {
    const dir = scratchDir();
    seedTree(dir);

    const ctx = makeCtx({ agentCwd: dir, fileWorkspaceRoot: dir });
    const inside = await runList(ctx, {
      directory: "src",
      toolCallDescription: "list inside the workspace",
    });
    expect(inside.success).toBe(true);
    expect(inside.files).toContain("a.ts");

    const outside = scratchDir();
    const outsideListing = await runList(ctx, {
      directory: outside,
      toolCallDescription: "list outside the workspace",
    });
    expect(outsideListing.success).toBe(false);
    expect(outsideListing.error).toMatch(/escapes/i);
  });
});

// The linux sandbox fake executes the actual listing scripts through bash,
// including the remote resolve round trip.
describe("listFiles sandbox (linux, real execution)", () => {
  it("non-recursive sandbox listing matches the local listing", async () => {
    const dir = scratchDir();
    seedTree(dir);

    const local = await runList(makeCtx({ agentCwd: dir }), {
      toolCallDescription: "local baseline",
    });
    const remote = await runList(
      makeCtx({ agentCwd: dir, sandbox: realLinuxSandbox() }),
      {
        toolCallDescription: "sandbox listing",
      },
    );

    expect(remote.success).toBe(true);
    expect([...remote.files].sort()).toEqual([...local.files].sort());
    expect(remote.count).toBe(local.count);
    expect(remote.totalFound).toBeUndefined();
  });

  it("recursive sandbox listing matches the local listing", async () => {
    const dir = scratchDir();
    seedTree(dir);
    const outside = scratchDir();
    writeFileSync(join(outside, "secret.txt"), "target source");
    symlinkSync(outside, join(dir, "link-out"));

    const local = await runList(makeCtx({ agentCwd: dir }), {
      recursive: true,
      toolCallDescription: "local baseline",
    });
    const remote = await runList(
      makeCtx({ agentCwd: dir, sandbox: realLinuxSandbox() }),
      {
        recursive: true,
        toolCallDescription: "sandbox recursive listing",
      },
    );

    expect(remote.success).toBe(true);
    expect([...remote.files].sort()).toEqual([...local.files].sort());
    // The symlinked dir was neither descended nor suffixed remotely either.
    expect(remote.files).toContain("link-out");
    expect(remote.files.some((f) => f.startsWith("link-out/"))).toBe(false);
  });

  it("caps oversized recursive listings with the exact total", async () => {
    const dir = scratchDir();
    // 250 files > MAX_RECURSIVE (200).
    for (let i = 0; i < 250; i++) {
      writeFileSync(join(dir, `f${String(i).padStart(3, "0")}.txt`), "x");
    }

    const result = await runList(
      makeCtx({ agentCwd: dir, sandbox: realLinuxSandbox() }),
      {
        recursive: true,
        toolCallDescription: "oversized sandbox listing",
      },
    );

    expect(result.success).toBe(true);
    expect(result.count).toBe(200);
    expect(result.totalFound).toBe(250);
    expect(result.error).toContain("Showing 200 of 250");
  });

  it("fails explicitly for a missing directory", async () => {
    const dir = scratchDir();

    const result = await runList(
      makeCtx({ agentCwd: dir, sandbox: realLinuxSandbox() }),
      {
        directory: "absent",
        toolCallDescription: "missing directory",
      },
    );

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/sandbox listing failed/);
  });
});

// No local PowerShell on this host: pin the windows transport shape — static
// command, env-only data, marker protocol. Real cmd.exe execution is covered
// by the shared remote-helper suite.
describe("listFiles sandbox transport shape (windows)", () => {
  function windowsSandbox(build: (envVars: Record<string, string>) => string): {
    sandbox: UnifiedSandbox;
    calls: { command: string; envVars?: Record<string, string> }[];
  } {
    const calls: { command: string; envVars?: Record<string, string> }[] = [];
    return {
      calls,
      sandbox: {
        type: "windows",
        execute: async (command, opts) => {
          calls.push({ command, envVars: opts?.envVars });
          if (opts?.envVars?.APEX_FILE_SCRIPT !== undefined) {
            return {
              stdout: JSON.stringify({ ok: true, path: "C:\\w" }),
              stderr: "",
              exitCode: 0,
              success: true,
            };
          }
          return {
            stdout: build(opts?.envVars ?? {}),
            stderr: "",
            exitCode: 0,
            success: true,
          };
        },
      },
    };
  }

  it("uses the static command with env-only data and parses the marker", async () => {
    const { sandbox, calls } = windowsSandbox(
      (env) => `src/\nREADME.md\nAPEXLS-${env.APEX_LIST_NONCE} total=2\n`,
    );

    const result = await runList(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      toolCallDescription: "windows listing",
    });

    const listCall = calls[calls.length - 1];
    const command = listCall.command;
    expect(command).toMatch(
      /^powershell -NoProfile -NonInteractive -EncodedCommand [A-Za-z0-9+/=]+$/,
    );
    // The bootstrap is fixed and short — far under cmd.exe's 8191 limit.
    expect(command.length).toBeLessThan(1000);
    expect(listCall.command).not.toContain("C:\\w");
    expect(listCall.envVars?.APEX_LIST_PATH).toBe("C:\\w");
    expect(listCall.envVars?.APEX_LIST_RECURSIVE).toBe("0");
    expect(listCall.envVars?.APEX_WIN_SCRIPT_COUNT).toBeDefined();
    const script = winScriptFromEnv(listCall.envVars);
    expect(script).toContain("[Console]::OutputEncoding");
    expect(script).not.toContain("C:\\w");

    expect(result.success).toBe(true);
    expect(result.files).toEqual(["src/", "README.md"]);
    expect(result.totalFound).toBeUndefined();
  });

  it("reports overflow from the marker total", async () => {
    const entries = Array.from(
      { length: 501 },
      (_, i) => `f${String(i).padStart(3, "0")}.txt`,
    );
    const { sandbox } = windowsSandbox(
      (env) =>
        `${entries.join("\n")}\nAPEXLS-${env.APEX_LIST_NONCE} total=501\n`,
    );

    const result = await runList(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      toolCallDescription: "windows overflow listing",
    });

    expect(result.success).toBe(true);
    expect(result.count).toBe(500);
    expect(result.totalFound).toBe(501);
    expect(result.error).toContain("Showing 500 of 501");
  });

  it("fails explicitly when the marker is missing", async () => {
    const { sandbox } = windowsSandbox(() => "orphan output\n");

    const result = await runList(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      toolCallDescription: "windows markerless listing",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("APEXLS");
  });
});
