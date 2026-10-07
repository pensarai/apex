import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { CommandEvent, ToolBackends } from "../../../tools/backends/types";
import { PerCommandShell } from "./perCommandShell";
import {
  checkScriptSyntax,
  SCRIPT_SYNTAX_CHECK_TIMEOUT_SECONDS,
} from "./scriptSyntaxCheck";
import type { ToolContext } from "./types";

const roots: string[] = [];

afterEach(() => {
  while (roots.length > 0)
    rmSync(roots.pop() as string, { recursive: true, force: true });
});

function context(root: string): ToolContext {
  return {
    session: { rootPath: root, targets: [] },
    agentCwd: root,
    fileWorkspaceRoot: root,
  } as unknown as ToolContext;
}

function stage(root: string, name: string, content: string): string {
  const pocs = join(root, ".pensar", "pocs");
  mkdirSync(pocs, { recursive: true });
  const path = join(pocs, name);
  writeFileSync(path, content);
  return path;
}

function sha256(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

function fakeBackend(overrides: {
  readRaw?: ToolBackends["fs"]["readRaw"];
  run?: ToolBackends["command"]["run"];
}): { run: ToolBackends["command"]["run"]; backends: ToolBackends } {
  const run =
    overrides.run ??
    vi.fn(async function* (): AsyncGenerator<CommandEvent> {
      yield { type: "end", exitCode: 0, timedOut: false };
    });
  const readRaw =
    overrides.readRaw ??
    vi.fn(async (path: string) => ({
      success: true,
      error: "",
      content: "echo prepared",
      path,
    }));
  const backends = {
    fs: { readRaw },
    command: { run },
  } as unknown as ToolBackends;
  return { run, backends };
}

describe("checkScriptSyntax (native transport, real runners)", () => {
  it("reports a valid prepared bash script with the hash of the exact staged bytes", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const content = '#!/bin/bash\n# POC: demo\n\nset -e\necho "proof"\n';
    const path = stage(root, "poc_admin_data.sh", content);
    const result = await checkScriptSyntax(context(root), {
      language: "bash",
      runner: "bash",
      scriptPath: path,
    });
    expect(result).toEqual({
      status: "valid",
      contentHash: sha256(content),
    });
  });

  it("checks generated JavaScript bytes (shebang and header included), not the agent source", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const generated =
      '#!/usr/bin/env node\n// POC: demo\n// Created: 2026-10-07\n\nconsole.log("proof");\n';
    const path = stage(root, "poc_admin_data.js", generated);
    const result = await checkScriptSyntax(context(root), {
      language: "javascript",
      runner: "node",
      scriptPath: path,
    });
    expect(result.status).toBe("valid");
    expect(result.contentHash).toBe(sha256(generated));
  });

  it("keeps native JS module semantics identical to execution for module-syntax scripts", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const path = stage(
      root,
      "poc_esm.js",
      'import { readFile } from "node:fs";\nconsole.log(typeof readFile);\n',
    );
    const executed = spawnSync("node", [path]);
    const result = await checkScriptSyntax(context(root), {
      language: "javascript",
      runner: "node",
      scriptPath: path,
    });
    // Whatever this node version does with `import` in a .js file, the
    // parse-only verdict must agree with actually running the same bytes.
    expect(result.status).toBe(executed.status === 0 ? "valid" : "invalid");
  });

  it("reports a bash syntax error with concise file/line feedback", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const path = stage(
      root,
      "poc_broken.sh",
      '#!/bin/bash\n# POC: demo\n\nif [ -n x ]; then\n  echo "unclosed"\n',
    );
    const result = await checkScriptSyntax(context(root), {
      language: "bash",
      runner: "bash",
      scriptPath: path,
    });
    expect(result.status).toBe("invalid");
    expect(result.detail).toMatch(/^.*poc_broken\.sh:6: syntax error/);
  });

  it("reports a python syntax error with file/line feedback", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const path = stage(
      root,
      "poc_broken.py",
      "#!/usr/bin/env python3\n# POC: demo\n\ndef broken(:\n",
    );
    const result = await checkScriptSyntax(context(root), {
      language: "python",
      runner: "python3",
      scriptPath: path,
    });
    expect(result.status).toBe("invalid");
    expect(result.detail).toMatch(
      /^.*poc_broken\.py:4: SyntaxError: invalid syntax$/,
    );
  });

  it("rejects a top-level python return that a real run would reject (full compile, not ast.parse)", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const path = stage(
      root,
      "poc_return.py",
      "#!/usr/bin/env python3\n\nreturn 1\n",
    );
    const result = await checkScriptSyntax(context(root), {
      language: "python",
      runner: "python3",
      scriptPath: path,
    });
    expect(result.status).toBe("invalid");
    expect(result.detail).toMatch(/return.*outside function/);
  });

  it("yields unchecked for a missing checker and still reports the checked-byte identity", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const content = "echo proof\n";
    const path = stage(root, "poc_admin_data.sh", content);
    const result = await checkScriptSyntax(context(root), {
      language: "bash",
      runner: "apex-no-such-runner",
      scriptPath: path,
    });
    expect(result.status).toBe("unchecked");
    expect(result.reason).toMatch(/syntax checker unavailable/);
    expect(result.contentHash).toBe(sha256(content));
  });

  it("runs the checker with the agent cwd and the bounded default deadline", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const path = stage(root, "poc_admin_data.sh", "echo proof\n");
    const argv = vi.spyOn(PerCommandShell.prototype, "executeArgv");
    try {
      const result = await checkScriptSyntax(context(root), {
        language: "bash",
        runner: "bash",
        scriptPath: path,
      });
      expect(result.status).toBe("valid");
      expect(argv).toHaveBeenCalledWith(
        "bash",
        ["-n", path],
        expect.objectContaining({
          cwd: root,
          timeoutSeconds: SCRIPT_SYNTAX_CHECK_TIMEOUT_SECONDS,
        }),
      );
    } finally {
      argv.mockRestore();
    }
  });
});

describe("checkScriptSyntax (injected backend routing)", () => {
  it("checks through the selected remote adapter with the staged path and no host fallback", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const path = "/remote/repo/.pensar/pocs/poc_admin 'data.sh";
    const { run, backends } = fakeBackend({});
    const ctx = { ...context(root), backends };
    const hostArgv = vi.spyOn(PerCommandShell.prototype, "executeArgv");
    try {
      const result = await checkScriptSyntax(ctx, {
        language: "bash",
        runner: "bash",
        scriptPath: path,
      });
      expect(result.status).toBe("valid");
      // POSIX command bytes carry the exact staged path, quoted.
      expect(run).toHaveBeenCalledWith(
        "bash -n '/remote/repo/.pensar/pocs/poc_admin '\\''data.sh'",
        expect.objectContaining({
          timeoutSeconds: SCRIPT_SYNTAX_CHECK_TIMEOUT_SECONDS,
        }),
      );
      // Pre-check read plus post-check certification read.
      expect(backends.fs.readRaw).toHaveBeenCalledTimes(2);
      expect(backends.fs.readRaw).toHaveBeenCalledWith(path);
      expect(hostArgv).not.toHaveBeenCalled();
    } finally {
      hostArgv.mockRestore();
    }
  });

  it("yields unchecked when a slow checker times out", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const { backends } = fakeBackend({
      run: vi.fn(async function* (): AsyncGenerator<CommandEvent> {
        yield { type: "end", exitCode: 124, timedOut: true };
      }),
    });
    const result = await checkScriptSyntax(
      { ...context(root), backends },
      { language: "bash", runner: "bash", scriptPath: "/remote/poc.sh" },
    );
    expect(result.status).toBe("unchecked");
    expect(result.reason).toMatch(/timed out/);
  });

  it("yields unchecked on the transport's abort exit code", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const { backends } = fakeBackend({
      run: vi.fn(async function* (): AsyncGenerator<CommandEvent> {
        yield { type: "end", exitCode: 130, timedOut: false };
      }),
    });
    const result = await checkScriptSyntax(
      { ...context(root), backends },
      { language: "bash", runner: "bash", scriptPath: "/remote/poc.sh" },
    );
    expect(result).toMatchObject({ status: "unchecked" });
    expect(result.reason).toMatch(/aborted/);
  });

  it("yields unchecked when a nonzero checker gives no file/line diagnostic", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const { backends } = fakeBackend({
      run: vi.fn(async function* (): AsyncGenerator<CommandEvent> {
        yield { type: "stderr", seq: 0, bytes: "something odd happened" };
        yield { type: "end", exitCode: 3, timedOut: false };
      }),
    });
    const result = await checkScriptSyntax(
      { ...context(root), backends },
      { language: "bash", runner: "bash", scriptPath: "/remote/poc.sh" },
    );
    expect(result.status).toBe("unchecked");
    expect(result.reason).toContain("exited 3");
    expect(result.reason).toContain("something odd happened");
  });

  it("yields unchecked when the injected backend throws, without a host fallback", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const { backends } = fakeBackend({
      run: vi.fn(async function* (): AsyncGenerator<CommandEvent> {
        yield { type: "start" };
        throw new Error("backend unavailable");
      }),
    });
    const hostArgv = vi.spyOn(PerCommandShell.prototype, "executeArgv");
    try {
      const result = await checkScriptSyntax(
        { ...context(root), backends },
        { language: "bash", runner: "bash", scriptPath: "/remote/poc.sh" },
      );
      expect(result.status).toBe("unchecked");
      expect(result.reason).toContain("backend unavailable");
      expect(hostArgv).not.toHaveBeenCalled();
    } finally {
      hostArgv.mockRestore();
    }
  });

  it("yields unchecked without invoking any checker when the staged bytes cannot be read", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const { run, backends } = fakeBackend({
      readRaw: async (path: string) => ({
        success: false,
        error: "remote storage failed",
        content: "",
        path,
      }),
    });
    const result = await checkScriptSyntax(
      { ...context(root), backends },
      { language: "bash", runner: "bash", scriptPath: "/remote/poc.sh" },
    );
    expect(result.status).toBe("unchecked");
    expect(result.reason).toContain("could not read the script bytes");
    expect(result.reason).toContain("remote storage failed");
    expect(run).not.toHaveBeenCalled();
  });

  it("yields unchecked when reading the staged bytes throws", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    const { backends } = fakeBackend({
      readRaw: async () => {
        throw new Error("read blew up");
      },
    });
    const result = await checkScriptSyntax(
      { ...context(root), backends },
      { language: "bash", runner: "bash", scriptPath: "/remote/poc.sh" },
    );
    expect(result.status).toBe("unchecked");
    expect(result.reason).toContain("syntax check failed");
    expect(result.reason).toContain("read blew up");
  });

  it("discards a verdict whose staged bytes changed during the check", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    let readCount = 0;
    const { backends } = fakeBackend({
      readRaw: async (path: string) => ({
        success: true,
        error: "",
        content: readCount++ === 0 ? "echo one" : "echo two",
        path,
      }),
    });
    const result = await checkScriptSyntax(
      { ...context(root), backends },
      { language: "bash", runner: "bash", scriptPath: "/remote/poc.sh" },
    );
    expect(result.status).toBe("unchecked");
    expect(result.reason).toContain(
      "script bytes changed during the syntax check",
    );
  });

  it("discards a verdict when the certification re-read fails", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-script-check-"));
    roots.push(root);
    let readCount = 0;
    const { backends } = fakeBackend({
      readRaw: async (path: string) => {
        if (readCount++ === 0)
          return { success: true, error: "", content: "echo one", path };
        return { success: false, error: "file vanished", content: "", path };
      },
    });
    const result = await checkScriptSyntax(
      { ...context(root), backends },
      { language: "bash", runner: "bash", scriptPath: "/remote/poc.sh" },
    );
    expect(result.status).toBe("unchecked");
    expect(result.reason).toContain("could not re-read");
    expect(result.reason).toContain("file vanished");
  });
});
