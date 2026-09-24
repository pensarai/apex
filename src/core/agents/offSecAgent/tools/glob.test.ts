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
import { type GlobResult, globFiles } from "./glob";
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
  const dir = mkdtempSync(join(tmpdir(), "apex-glob-test-"));
  scratchDirs.push(dir);
  return dir;
}

function seedTree(dir: string) {
  mkdirSync(join(dir, "src", "deep"), { recursive: true });
  mkdirSync(join(dir, "node_modules", "pkg"), { recursive: true });
  mkdirSync(join(dir, ".hidden"), { recursive: true });
  writeFileSync(join(dir, "src", "a.ts"), "export {}");
  writeFileSync(join(dir, "src", "b.tsx"), "export {}");
  writeFileSync(join(dir, "src", "deep", "c.ts"), "export {}");
  writeFileSync(join(dir, "package.json"), "{}");
  writeFileSync(join(dir, "node_modules", "pkg", "index.ts"), "export {}");
  writeFileSync(join(dir, ".hidden", "h.ts"), "export {}");
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

async function runGlob(
  ctx: ToolContext,
  input: { pattern: string; path?: string; toolCallDescription: string },
): Promise<GlobResult> {
  return (await globFiles(ctx).execute?.(input, {
    toolCallId: "tc_test",
    messages: [],
    abortSignal: ctx.abortSignal,
  })) as GlobResult;
}

afterEach(() => {
  for (const dir of scratchDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("globFiles local", () => {
  it("matches files by pattern, skipping node_modules and dotfiles", async () => {
    const root = scratchDir();
    seedTree(root);

    const result = await runGlob(makeCtx({ agentCwd: root }), {
      pattern: "**/*.{ts,tsx}",
      toolCallDescription: "Find TS sources",
    });

    expect(result.success).toBe(true);
    expect(result.files).toEqual(["src/a.ts", "src/b.tsx", "src/deep/c.ts"]);
    expect(result.files.some((f) => f.includes("node_modules"))).toBe(false);
    expect(result.files.some((f) => f.startsWith(".hidden"))).toBe(false);
  });

  it("matches from a subdirectory root", async () => {
    const root = scratchDir();
    seedTree(root);

    const result = await runGlob(makeCtx({ agentCwd: root }), {
      pattern: "**/*.ts",
      path: "src",
      toolCallDescription: "Find TS under src",
    });

    expect(result.files).toEqual(["a.ts", "deep/c.ts"]);
  });

  it("does not descend symlinked directories", async () => {
    const root = scratchDir();
    seedTree(root);
    const outside = scratchDir();
    writeFileSync(join(outside, "leak.ts"), "target source");
    symlinkSync(outside, join(root, "link-out"));

    const result = await runGlob(makeCtx({ agentCwd: root }), {
      pattern: "**/*.ts",
      toolCallDescription: "Glob with a directory symlink",
    });

    expect(result.files.some((f) => f.startsWith("link-out/"))).toBe(false);
  });

  it.each([
    ["parent traversal", "../**/*.ts"],
    ["absolute pattern", "/etc/**"],
    ["windows drive pattern", "C:\\w\\**"],
    ["mid-segment **", "a**b/*.ts"],
  ])("rejects %s patterns clearly", async (_label, pattern) => {
    const root = scratchDir();

    const result = await runGlob(makeCtx({ agentCwd: root }), {
      pattern,
      toolCallDescription: "Invalid pattern",
    });

    expect(result.success).toBe(false);
    expect(result.files).toEqual([]);
    expect(result.error).not.toBe("");
  });

  it("rejects search roots that escape the agent cwd", async () => {
    const root = scratchDir();
    const outside = scratchDir();

    const result = await runGlob(makeCtx({ agentCwd: root }), {
      pattern: "**/*.ts",
      path: outside,
      toolCallDescription: "Escape attempt",
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/escapes/i);
  });

  it("stays confined to fileWorkspaceRoot when set", async () => {
    const root = scratchDir();
    seedTree(root);
    const other = scratchDir();
    writeFileSync(join(other, "other.ts"), "export {}");

    const ctx = makeCtx({ agentCwd: root, fileWorkspaceRoot: root });
    const inside = await runGlob(ctx, {
      pattern: "**/*.ts",
      path: "src",
      toolCallDescription: "Scoped glob",
    });
    expect(inside.success).toBe(true);
    expect(inside.files).toContain("a.ts");

    const escapeAttempt = await runGlob(ctx, {
      pattern: "**/*.ts",
      path: other,
      toolCallDescription: "Escape the workspace",
    });
    expect(escapeAttempt.success).toBe(false);
    expect(escapeAttempt.error).toMatch(/escapes/i);
  });

  it("caps results with an exact total", async () => {
    const root = scratchDir();
    for (let i = 0; i < 250; i++) {
      writeFileSync(join(root, `f${String(i).padStart(3, "0")}.ts`), "x");
    }

    const result = await runGlob(makeCtx({ agentCwd: root }), {
      pattern: "*.ts",
      toolCallDescription: "Oversized result set",
    });

    expect(result.count).toBe(200);
    expect(result.totalFound).toBe(250);
    expect(result.error).toContain("Showing 200 of 250");
  });
});

// The linux sandbox fake executes the real enumeration scripts through bash,
// including the remote resolve round trip.
describe("globFiles sandbox (linux, real execution)", () => {
  it("matches identically to the local backend", async () => {
    const root = scratchDir();
    seedTree(root);

    const local = await runGlob(makeCtx({ agentCwd: root }), {
      pattern: "**/*.{ts,tsx}",
      toolCallDescription: "Local baseline",
    });
    const remote = await runGlob(
      makeCtx({ agentCwd: root, sandbox: realLinuxSandbox() }),
      {
        pattern: "**/*.{ts,tsx}",
        toolCallDescription: "Sandbox glob",
      },
    );

    expect(remote.success).toBe(true);
    expect(remote.files).toEqual(local.files);
  });

  it("does not descend sandbox symlinked directories or dotdirs", async () => {
    const root = scratchDir();
    seedTree(root);
    const outside = scratchDir();
    writeFileSync(join(outside, "leak.ts"), "target source");
    symlinkSync(outside, join(root, "link-out"));

    const result = await runGlob(
      makeCtx({ agentCwd: root, sandbox: realLinuxSandbox() }),
      {
        pattern: "**/*.ts",
        toolCallDescription: "Sandbox glob with symlink",
      },
    );

    expect(result.files.some((f) => f.startsWith("link-out/"))).toBe(false);
    expect(result.files.some((f) => f.startsWith(".hidden"))).toBe(false);
  });

  it("reports possible incompleteness when the scan cap is hit", async () => {
    const root = scratchDir();
    for (let i = 0; i < 250; i++) {
      writeFileSync(join(root, `f${String(i).padStart(3, "0")}.ts`), "x");
    }

    const result = await runGlob(
      makeCtx({ agentCwd: root, sandbox: realLinuxSandbox() }),
      {
        pattern: "*.ts",
        toolCallDescription: "Sandbox glob",
      },
    );

    expect(result.success).toBe(true);
    expect(result.count).toBe(200);
    // 250 files fits under the 20k scan cap, so the total is still exact.
    expect(result.totalFound).toBe(250);
  });
});

// No local PowerShell on this host: pin the windows transport shape — static
// command, env-only data, marker protocol. Real cmd.exe execution is covered
// by the shared remote-helper suite.
describe("globFiles sandbox transport shape (windows)", () => {
  function windowsSandbox(entries: string[]): {
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
          const nonce = opts?.envVars?.APEX_GLOB_NONCE ?? "";
          return {
            stdout: `${entries.join("\n")}\nAPEXGL-${nonce} end\n`,
            stderr: "",
            exitCode: 0,
            success: true,
          };
        },
      },
    };
  }

  it("uses the static command with env-only data and matches enumerated entries", async () => {
    // The fake returns post-pruning entries, as the real script emits them.
    const { sandbox, calls } = windowsSandbox([
      "src/a.ts",
      "src/b.tsx",
      "README.md",
    ]);

    const result = await runGlob(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      pattern: "**/*.{ts,tsx}",
      toolCallDescription: "Windows glob",
    });

    const listCall = calls[calls.length - 1];
    const command = listCall.command;
    expect(command).toMatch(
      /^powershell -NoProfile -NonInteractive -EncodedCommand [A-Za-z0-9+/=]+$/,
    );
    // The bootstrap is fixed and short — far under cmd.exe's 8191 limit.
    expect(command.length).toBeLessThan(1000);
    expect(listCall.command).not.toContain("C:\\w");
    expect(listCall.envVars?.APEX_GLOB_PATH).toBe("C:\\w");
    expect(listCall.envVars?.APEX_WIN_SCRIPT_COUNT).toBeDefined();
    const script = winScriptFromEnv(listCall.envVars);
    expect(script).toContain("[Console]::OutputEncoding");
    expect(script).not.toContain("C:\\w");
    expect(script).toContain("'node_modules'");

    expect(result.success).toBe(true);
    expect(result.files).toEqual(["src/a.ts", "src/b.tsx"]);
  });

  it("fails explicitly when the completion marker is missing", async () => {
    const calls: { command: string; envVars?: Record<string, string> }[] = [];
    const sandbox: UnifiedSandbox = {
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
        return { stdout: "orphan\n", stderr: "", exitCode: 0, success: true };
      },
    };

    const result = await runGlob(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      pattern: "**/*.ts",
      toolCallDescription: "Markerless windows glob",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("APEXGL");
  });
});

it("keeps regular files whose names match ignored directory names", async () => {
  const root = scratchDir();
  writeFileSync(join(root, "dist"), "ordinary file");
  for (const sandbox of [undefined, realLinuxSandbox()]) {
    const result = await runGlob(makeCtx({ agentCwd: root, sandbox }), {
      pattern: "**/dist",
      toolCallDescription: "find a regular file",
    });
    expect(result.success).toBe(true);
    expect(result.files).toEqual(["dist"]);
  }
});

it("character classes cannot consume a path separator", async () => {
  const root = scratchDir();
  mkdirSync(join(root, "a"));
  writeFileSync(join(root, "a", "b"), "nested");
  const result = await runGlob(makeCtx({ agentCwd: root }), {
    pattern: "a[!x]b",
    toolCallDescription: "match one path segment",
  });
  expect(result.success).toBe(true);
  expect(result.files).toEqual([]);
  const invalid = await runGlob(makeCtx({ agentCwd: root }), {
    pattern: "[z-a]",
    toolCallDescription: "reject an invalid range",
  });
  expect(invalid.success).toBe(false);
  expect(invalid.error).toBeTruthy();
});

it("reports scan overflow even when the extra entry ends the last directory", async () => {
  const root = scratchDir();
  for (let i = 0; i < 20_001; i++) writeFileSync(join(root, `f${i}`), "");
  const result = await runGlob(makeCtx({ agentCwd: root }), {
    pattern: "*",
    toolCallDescription: "inspect a capped scan",
  });
  expect(result.success).toBe(true);
  expect(result.error).toContain("may be incomplete");
  expect(result.totalFound).toBeUndefined();
  expect(result.files.length).toBeLessThanOrEqual(200);
});

it("does not report a remote enumeration as completed after cancellation", async () => {
  const root = scratchDir();
  writeFileSync(join(root, "f.txt"), "contents");
  const abort = new AbortController();
  const real = realLinuxSandbox();
  const sandbox: UnifiedSandbox = {
    type: "linux",
    execute: async (command, options) => {
      const result = await real.execute(command, options);
      if (options?.envVars?.APEX_GLOB_PATH) abort.abort();
      return result;
    },
  };
  const result = await runGlob(
    makeCtx({ agentCwd: root, sandbox, abortSignal: abort.signal }),
    {
      pattern: "*",
      toolCallDescription: "cancel a directory scan",
    },
  );
  expect(result.success).toBe(false);
  expect(result.files).toEqual([]);
});
