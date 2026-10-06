import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const launcher = join(import.meta.dirname, "../../bin/pensar.js");
const node = spawnSync("node", ["-p", "process.execPath"], {
  encoding: "utf8",
}).stdout.trim();
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

async function run(args: string[], env: NodeJS.ProcessEnv = {}) {
  const root = await mkdtemp(join(tmpdir(), "apex-launcher-"));
  temporaryDirectories.push(root);
  await Promise.all([mkdir(join(root, "bin")), mkdir(join(root, "build"))]);
  await Promise.all([
    copyFile(launcher, join(root, "bin/pensar.js")),
    writeFile(join(root, "package.json"), '{"type":"module"}'),
    writeFile(
      join(root, "build/cli.js"),
      `console.log(JSON.stringify({
  runtime: typeof globalThis.Bun === "undefined" ? "node" : "bun",
  args: process.argv.slice(2),
  noTui: process.env.PENSAR_NO_TUI,
}));`,
    ),
  ]);
  return spawnSync(node, [join(root, "bin/pensar.js"), ...args], {
    cwd: root,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      SYSTEMROOT: process.env.SYSTEMROOT,
      ...env,
    },
    timeout: 10_000,
  });
}

describe("npm launcher", () => {
  it.each([
    { args: [] },
    {
      args: ["--resume", "ses_fixture", "--model", "model/name", "--obfuscate"],
    },
    { args: ["--quiet", "--resume", "ses_fixture"] },
    { args: ["--log-level", "INFO", "--resume", "ses_fixture"] },
    { args: ["--obfuscate", "--verbose"] },
    { args: ["--log-level", "--quiet", "INFO"] },
  ])("forwards TUI arguments to Bun: $args", async ({ args }) => {
    const result = await run(args);
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({ runtime: "bun", args });
  });

  it("keeps headless commands on Node", async () => {
    const args = ["--quiet", "pentest", "--target", "https://example.test"];
    const result = await run(args);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      runtime: "node",
      args,
      noTui: "1",
    });
  });

  it("explains the Bun requirement when a resume cannot launch", async () => {
    const result = await run(["--resume", "ses_fixture"], { PATH: "" });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("TUI mode requires Bun");
    expect(result.stdout).toBe("");
  });
});
