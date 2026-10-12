import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { TuiOptions } from "../core/cli/tuiArgs";

const projectRoot = join(import.meta.dirname, "../..");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

async function start(options: TuiOptions, obfuscate: boolean) {
  const root = await mkdtemp(join(tmpdir(), "apex-herdr-startup-"));
  temporaryDirectories.push(root);
  const sessionRoot = join(root, ".pensar/sessions/ses_fixture");
  await mkdir(sessionRoot, { recursive: true });
  await writeFile(
    join(root, ".pensar/config.json"),
    JSON.stringify({
      responsibleUseAccepted: true,
      themeMode: "dark",
      anthropicAPIKey: "local-fixture",
      selectedModelId: "claude-opus-4-6",
      hoonifyAPIKey: "",
    }),
  );
  await writeFile(
    join(sessionRoot, "session.json"),
    JSON.stringify({
      id: "ses_fixture",
      name: "Herdr startup fixture",
      version: "2.5.0",
      targets: [],
      config: { mode: "operator" },
      time: { created: 1, updated: 1 },
      rootPath: sessionRoot,
      logsPath: join(sessionRoot, "logs"),
      findingsPath: join(sessionRoot, "findings"),
      scratchpadPath: join(sessionRoot, "scratchpad"),
      pocsPath: join(sessionRoot, "pocs"),
    }),
  );
  const runner = join(root, "startup.ts");
  await writeFile(
    runner,
    `import os from "node:os";
import { mock } from "bun:test";
const fixtureOs = { ...os, homedir: () => ${JSON.stringify(root)} };
for (const name of ["os", "node:os"]) {
  mock.module(name, () => ({ ...fixtureOs, default: fixtureOs }));
}
globalThis.fetch = async () => { throw new Error("Unexpected network access"); };
const events = [];
const corePath = Bun.resolveSync("@opentui/core", ${JSON.stringify(projectRoot)});
const core = await import(corePath);
mock.module(corePath, () => ({
  ...core,
  createCliRenderer: async () => ({
    console: { handleMouse() {} },
    on() {},
    addPostProcessFn() {},
    destroy() {},
  }),
}));
const reactPath = Bun.resolveSync("@opentui/react", ${JSON.stringify(projectRoot)});
const react = await import(reactPath);
mock.module(reactPath, () => ({
  ...react,
  createRoot: () => ({ render() { events.push({ type: "render" }); } }),
}));
mock.module(${JSON.stringify(join(projectRoot, "src/core/integrations/herdr.ts"))}, () => ({
  createHerdrReporter: () => ({
    report: (report) => events.push({ type: "report", report }),
    release: async () => {},
  }),
}));
const { startTui } = await import(${JSON.stringify(join(projectRoot, "src/tui/index.tsx"))});
try {
  await startTui(${JSON.stringify(options)});
  process.stdout.write(JSON.stringify(events));
  process.exit(0);
} catch (error) {
  console.error(error);
  process.exit(1);
}
`,
  );
  return spawnSync("bun", ["--no-env-file", runner], {
    cwd: root,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      OTEL_SDK_DISABLED: "true",
      PENSAR_OBFUSCATE: obfuscate ? "1" : "0",
    },
    timeout: 30_000,
  });
}

describe("Herdr startup report", () => {
  it.each([
    { modelId: "claude-sonnet-4-6", expectedModel: "claude-sonnet-4-6" },
    { modelId: undefined, expectedModel: "claude-opus-4-6" },
  ])("can resume with $expectedModel before the dashboard mounts", async ({
    modelId,
    expectedModel,
  }) => {
    const result = await start({ sessionId: "ses_fixture", modelId }, true);
    expect(result.error, result.stderr).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual([
      {
        type: "report",
        report: {
          state: "working",
          session: {
            id: "ses_fixture",
            resumeArgv: [
              "pensar",
              "--resume",
              "ses_fixture",
              "--model",
              expectedModel,
              "--obfuscate",
            ],
          },
        },
      },
      { type: "render" },
    ]);
  });

  it.each([
    false,
    true,
  ])("reports the home launch with obfuscation=%s", async (obfuscate) => {
    const result = await start({}, obfuscate);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual([
      {
        type: "report",
        report: {
          state: "idle",
          session: {
            resumeArgv: ["pensar", ...(obfuscate ? ["--obfuscate"] : [])],
          },
        },
      },
      { type: "render" },
    ]);
  });
});
