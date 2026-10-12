import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import { profileCodebase } from "../../whitebox/repoProfile";
import type { CommandBackend } from "./types";
import { resolveWhiteboxBackend } from "./whitebox";

function response(command: string) {
  if (command.includes("'test' '-d'")) return { stdout: "", exitCode: 0 };
  if (command.includes("find ."))
    return { stdout: "src/server.ts\npackage.json\n", exitCode: 0 };
  if (command.includes("'cat'"))
    return { stdout: '{"scripts":{"test":"vitest"}}', exitCode: 0 };
  if (command.includes("'rev-parse'"))
    return { stdout: "deadbeef", exitCode: 0 };
  return { stdout: "", exitCode: 1 };
}

describe("resolved whitebox execution", () => {
  it("keeps injected profile command identities and order unchanged", async () => {
    const calls: Array<[string, unknown]> = [];
    const command: CommandBackend = {
      async *run(cmd, options) {
        calls.push([cmd, JSON.parse(JSON.stringify(options))]);
        const result = response(cmd);
        yield { type: "stdout", seq: 0, bytes: result.stdout };
        yield { type: "end", exitCode: result.exitCode, timedOut: false };
      },
    };
    const root = "/nonexistent-remote-repository";
    // Fixed command journal from before the transport consolidation.
    const baseline = [
      [
        "cd '/nonexistent-remote-repository' && 'test' '-d' '.'",
        {
          timeoutSeconds: 5,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'bash' '-c' 'find . -mindepth 1 \\( -type d \\( -name '\\''.git'\\'' -o -name '\\''node_modules'\\'' -o -name '\\''vendor'\\'' -o -name '\\''third_party'\\'' -o -name '\\''dist'\\'' -o -name '\\''build'\\'' -o -name '\\''coverage'\\'' -o -name '\\''.next'\\'' -o -name '\\''target'\\'' -o -name '\\''__pycache__'\\'' \\) -prune \\) -o -type f -print | LC_ALL=C sort'",
        {
          timeoutSeconds: 30,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'cat' 'package.json'",
        {
          timeoutSeconds: 5,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'git' 'rev-parse' 'HEAD'",
        {
          timeoutSeconds: 5,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'git' 'submodule' 'status'",
        {
          timeoutSeconds: 5,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'tokei'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'rg'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'ast-grep'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'comby'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'semgrep'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'codeql'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'bandit'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'gosec'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'cargo-geiger'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'cargo-audit'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'gitleaks'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'trufflehog'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'noseyparker'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'osv-scanner'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'trivy'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'grype'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'npm'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'pip-audit'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'govulncheck'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'brakeman'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'spotbugs'",
        {
          timeoutSeconds: 2,
        },
      ],
      [
        "cd '/nonexistent-remote-repository' && 'which' 'jazzer'",
        {
          timeoutSeconds: 2,
        },
      ],
    ];
    const ctx = { backends: { command } } as ToolContext;
    const actual = await profileCodebase(
      root,
      resolveWhiteboxBackend(ctx).profile,
    );
    expect(actual.languages).toEqual(["typescript"]);
    expect(actual.testCommands).toEqual(["npm run test"]);
    expect(calls).toEqual(baseline);
    expect(calls).toHaveLength(27);
  });

  it("profiles an owned sandbox without reading its path on the host", async () => {
    const sessionRoot = await mkdtemp(join(tmpdir(), "whitebox-remote-"));
    try {
      const execute = vi.fn(async (cmd: string) => {
        const result = response(cmd);
        return { ...result, success: result.exitCode === 0, stderr: "" };
      });
      const local = vi.fn();
      const ctx = {
        agentCwd: "/nonexistent-remote-repository",
        session: { rootPath: sessionRoot },
        sandbox: { type: "linux", execute },
        commandShell: { execute: local },
      } as unknown as ToolContext;
      const profile = await profileCodebase(
        ctx.agentCwd,
        resolveWhiteboxBackend(ctx).profile,
      );
      expect(profile.languages).toEqual(["typescript"]);
      expect(profile.testCommands).toEqual(["npm run test"]);
      expect(execute).toHaveBeenCalledTimes(27);
      expect(local).not.toHaveBeenCalled();
    } finally {
      await rm(sessionRoot, { recursive: true, force: true });
    }
  });

  it("preserves native argv quoting and capture limits for local analysis", async () => {
    const ctx = { agentCwd: process.cwd() } as ToolContext;
    const literal = "spaces ' quotes $HOME ; literal";
    const result = await resolveWhiteboxBackend(ctx).run(
      [
        process.execPath,
        "-e",
        "process.stdout.write(process.argv[1])",
        literal,
      ],
      { cwd: process.cwd(), timeoutSeconds: 5, maxTotalBytes: 12 },
    );
    expect(result.stdout).toBe(literal.slice(0, 12));
    expect(result.outputTruncated).toBe(true);
    expect(result.exitCode).toBe(0);
  });

  it("does not fall back after an injected analyzer fails", async () => {
    const failure = new Error("analyzer backend unavailable");
    const execute = vi.fn();
    const ctx = {
      backends: {
        command: {
          async *run() {
            yield await Promise.reject<never>(failure);
          },
        },
      },
      sandbox: { execute },
    } as unknown as ToolContext;
    await expect(
      resolveWhiteboxBackend(ctx).run(["scanner"], {
        cwd: "/remote",
        timeoutSeconds: 5,
        maxTotalBytes: 1024,
      }),
    ).rejects.toBe(failure);
    expect(execute).not.toHaveBeenCalled();
  });
});
