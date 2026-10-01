import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const rootCli = join(import.meta.dirname, "../cli.ts");
const apiClient = join(import.meta.dirname, "../core/api/apiClient.ts");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

describe("CLI JSON output", () => {
  it.each([
    ["pentests", "dispatch"],
    ["pentests", "get", "scan-fixture"],
    ["--log-level", "invalid", "pentests", "dispatch"],
  ])("keeps stdout parseable with a .env file: %j", async (...args) => {
    const root = await mkdtemp(join(tmpdir(), "apex-json-output-"));
    temporaryDirectories.push(root);
    const fixtureHome = join(root, "home");
    await mkdir(fixtureHome);
    await writeFile(join(root, ".env"), "APEX_JSON_FIXTURE=scan-fixture\n");
    const preload = join(root, "preload.ts");
    await writeFile(
      preload,
      `import os from "node:os";
import { mock } from "bun:test";
const fixtureOs = { ...os, homedir: () => ${JSON.stringify(fixtureHome)} };
for (const name of ["os", "node:os"]) {
  mock.module(name, () => ({ ...fixtureOs, default: fixtureOs }));
}
mock.module(${JSON.stringify(apiClient)}, () => ({
  apiRequest: async () => ({ scanId: process.env.APEX_JSON_FIXTURE, status: "queued" }),
}));
`,
    );
    const result = spawnSync(
      "bun",
      ["--no-env-file", "--preload", preload, rootCli, ...args],
      {
        cwd: root,
        encoding: "utf8",
        env: { PATH: process.env.PATH, OTEL_SDK_DISABLED: "true" },
        timeout: 10_000,
      },
    );
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      scanId: "scan-fixture",
      status: "queued",
    });
    if (args.includes("invalid")) {
      expect(result.stderr).toContain('Ignoring invalid --log-level "invalid"');
    }
  });
});
