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

function run(args: string[], entrypoint = cli) {
  const result = spawnSync("bun", [entrypoint, ...args], {
    encoding: "utf8",
    env: { ...process.env, OTEL_EXPORTER_OTLP_ENDPOINT: "http://127.0.0.1:1" },
    timeout: 5_000,
  });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

async function requestFixture() {
  const root = await mkdtemp(join(tmpdir(), "apex-export-command-"));
  temporaryDirectories.push(root);
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
  return { requestPath, outputPath };
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

  it("routes from the root CLI without starting telemetry", () => {
    const result = run(["export-trajectory", "--help"], rootCli);

    expect(result.status).toBe(0);
    expect(result.stderr).not.toContain("ECONNREFUSED");
    expect(result.stdout).toContain("The command reads recorded evidence only");
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
      manifestPath: join(outputPath, "manifest.json"),
    });
    expect(response.rootTrajectoryId).toMatch(/^atif_/);
    expect(response.fileCount).toBeGreaterThan(2);
    expect(
      JSON.parse(await readFile(response.manifestPath, "utf8")),
    ).toMatchObject({ validation: { status: "passed" } });
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
