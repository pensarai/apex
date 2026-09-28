import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { nativeSource } from "../core/atif/test-fixtures";

const cli = join(import.meta.dirname, "export-trajectory.ts");
const rootCli = join(import.meta.dirname, "../cli.ts");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function run(
  args: string[],
  entrypoint = cli,
  fixture?: { root: string; preload: string },
) {
  const result = spawnSync(
    "bun",
    [
      "--no-env-file",
      ...(fixture ? ["--preload", fixture.preload] : []),
      entrypoint,
      ...args,
    ],
    {
      cwd: fixture?.root,
      encoding: "utf8",
      env: {
        PATH: process.env.PATH,
        OTEL_EXPORTER_OTLP_ENDPOINT: "http://127.0.0.1:1",
      },
      timeout: 5_000,
    },
  );
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

async function requestFixture() {
  const root = await mkdtemp(join(tmpdir(), "apex-export-command-"));
  temporaryDirectories.push(root);
  const fixtureHome = join(root, "fixture-home");
  await mkdir(fixtureHome);
  await writeFile(join(root, ".env"), "APEX_EXPORT_FIXTURE=benign\n");
  const preload = join(root, "isolate-home.ts");
  await writeFile(
    preload,
    `import os from "node:os";
import { mock } from "bun:test";
const fixtureHome = ${JSON.stringify(fixtureHome)};
const fixtureOs = { ...os, homedir: () => fixtureHome };
for (const name of ["os", "node:os"]) {
  mock.module(name, () => ({ ...fixtureOs, default: fixtureOs }));
}
for (const name of ["os", "node:os"]) {
  const module = await import(name);
  if (module.homedir() !== fixtureHome || module.default.homedir() !== fixtureHome)
    throw new Error("Fixture home isolation failed");
}
`,
  );
  const source = nativeSource({ id: `source-${randomUUID()}` });
  const sourcePath = join(root, "evidence.json");
  const requestPath = join(root, "request.json");
  const outputPath = join(root, "output");
  await writeFile(sourcePath, source.bytes);
  await writeFile(
    requestPath,
    JSON.stringify({
      version: 1,
      sources: [
        {
          id: source.id,
          path: basename(sourcePath),
          sha256: createHash("sha256").update(source.bytes).digest("hex"),
          sizeBytes: source.bytes.byteLength,
        },
      ],
      rootSourceId: source.id,
      agent: { name: "apex", version: "test" },
      exporter: { name: "apex-native-evidence", version: "1" },
    }),
  );
  return { root, preload, requestPath, outputPath };
}

describe("pensar export-trajectory", () => {
  it("documents the standalone recorded-evidence command", () => {
    const result = run(["--help"]);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain(
      "pensar export-trajectory --input <request.json> --output <directory>",
    );
    expect(result.stdout).toContain("existing paths are never overwritten");
    expect(result.stdout).toContain("caller-supplied result");
    expect(result.stdout).toMatch(/does not run an external\s+validator/);
  });

  it("routes from the root CLI without starting telemetry", async () => {
    const fixture = await requestFixture();
    const result = run(["export-trajectory", "--help"], rootCli, fixture);

    expect(result.status).toBe(0);
    expect(result.stderr).not.toContain("ECONNREFUSED");
    expect(result.stdout).toContain("The command reads recorded evidence only");
  });

  it.each([
    { flags: [] },
    { flags: ["--verbose"] },
    { flags: ["--quiet"] },
    { flags: ["--log-level", "ERROR"] },
    { flags: ["--obfuscate"] },
    { flags: ["--redact"] },
    { flags: ["-O"] },
    { flags: ["--obfuscate", "--verbose", "--log-level", "WARN"] },
    { flags: ["--log-level", "invalid"] },
  ])("keeps the root CLI success output machine-readable with prefix $flags", async ({
    flags,
  }) => {
    const fixture = await requestFixture();
    const { requestPath, outputPath } = fixture;

    const result = run(
      [
        ...flags,
        "export-trajectory",
        "--input",
        requestPath,
        "--output",
        outputPath,
      ],
      rootCli,
      fixture,
    );

    expect(result.status).toBe(0);
    expect(result.stderr).not.toContain("ECONNREFUSED");
    if (flags.includes("invalid")) {
      expect(result.stderr).toContain('Ignoring invalid --log-level "invalid"');
    }
    expect(JSON.parse(result.stdout)).toMatchObject({
      outputDirectory: outputPath,
      manifestPath: join(outputPath, "trajectory-bundle.json"),
    });
  });

  it("preserves ordinary command output with preceding global flags", async () => {
    const fixture = await requestFixture();
    const result = run(["--quiet", "version"], rootCli, fixture);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("injected env");
    expect(result.stdout).toMatch(/\nv\d+\.\d+\.\d+\n$/);
  });

  it("rejects missing and unknown options without creating output", async () => {
    const { requestPath, outputPath } = await requestFixture();

    const missing = run(["--input", requestPath]);
    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain("--input and --output are both required");

    const unknown = run([
      "--input",
      requestPath,
      "--output",
      outputPath,
      "--provider",
      "none",
    ]);
    expect(unknown.status).toBe(1);
    expect(unknown.stderr).toContain(
      "expected --input <request.json> --output <directory>",
    );
  });

  it("exports relative saved sources and returns a bounded result", async () => {
    const { requestPath, outputPath } = await requestFixture();

    const result = run(["--input", requestPath, "--output", outputPath]);

    expect(result.status).toBe(0);
    const response = JSON.parse(result.stdout) as {
      outputDirectory: string;
      manifestPath: string;
      rootTrajectoryId: string;
      fileCount: number;
    };
    expect(response).toMatchObject({
      outputDirectory: outputPath,
      manifestPath: join(outputPath, "trajectory-bundle.json"),
    });
    expect(response.rootTrajectoryId).toMatch(/^atif_/);
    expect(response.fileCount).toBeGreaterThan(2);
    expect(
      JSON.parse(await readFile(response.manifestPath, "utf8")),
    ).toMatchObject({ validation: { status: "valid" } });
  });

  it("does not overwrite an existing destination", async () => {
    const { requestPath, outputPath } = await requestFixture();
    await mkdir(outputPath);
    await writeFile(join(outputPath, "sentinel"), "keep");

    const result = run(["--input", requestPath, "--output", outputPath]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("DESTINATION_EXISTS");
    expect(await readFile(join(outputPath, "sentinel"), "utf8")).toBe("keep");
  });
});
