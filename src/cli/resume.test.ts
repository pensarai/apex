import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const rootCli = join(import.meta.dirname, "../cli.ts");
const tui = join(import.meta.dirname, "../tui/index.tsx");
const herdr = join(import.meta.dirname, "../core/integrations/herdr.ts");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

async function run(args: string[], env: NodeJS.ProcessEnv = {}) {
  const root = await mkdtemp(join(tmpdir(), "apex-resume-command-"));
  temporaryDirectories.push(root);
  const preload = join(root, "preload.ts");
  await writeFile(
    preload,
    `import os from "node:os";
import { mock } from "bun:test";
const fixtureOs = { ...os, homedir: () => ${JSON.stringify(root)} };
for (const name of ["os", "node:os"]) {
  mock.module(name, () => ({ ...fixtureOs, default: fixtureOs }));
}
mock.module(${JSON.stringify(herdr)}, () => ({
  createHerdrReporter: () => { throw new Error("The CLI must not claim the TUI pane"); },
}));
mock.module(${JSON.stringify(tui)}, () => ({
  startTui: async (options) => console.log(JSON.stringify({
    options,
    obfuscate: process.env.PENSAR_OBFUSCATE === "1",
    logLevel: process.env.PENSAR_LOG_LEVEL,
  })),
}));
`,
  );
  return spawnSync(
    "bun",
    ["--no-env-file", "--preload", preload, rootCli, ...args],
    {
      cwd: root,
      encoding: "utf8",
      env: { PATH: process.env.PATH, OTEL_SDK_DISABLED: "true", ...env },
      timeout: 10_000,
    },
  );
}

describe("pensar --resume", () => {
  it("passes the session and model to the TUI while preserving global flags", async () => {
    const result = await run([
      "--obfuscate",
      "--quiet",
      "--resume",
      "ses_fixture",
      "--model",
      "custom:local:model/name",
    ]);
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      options: {
        sessionId: "ses_fixture",
        modelId: "custom:local:model/name",
      },
      obfuscate: true,
      logLevel: "WARN",
    });
  });

  it("continues to launch the home screen without arguments", async () => {
    const result = await run([]);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      options: {},
      obfuscate: false,
    });
  });

  it("rejects mixing a resume request with a new operator prompt", async () => {
    const result = await run(["--resume", "ses_fixture", "-p", "new task"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Use pensar --resume");
    expect(result.stdout).toBe("");
  });

  it("rejects a missing session before launching the TUI", async () => {
    const result = await run(["--resume"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("--resume requires a saved session ID");
    expect(result.stdout).toBe("");
  });

  it("keeps the existing Node-only TUI guard on resume", async () => {
    const result = await run(["--resume", "ses_fixture"], {
      PENSAR_NO_TUI: "1",
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("TUI mode requires Bun");
    expect(result.stdout).toBe("");
  });
});
