import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { nativeSource } from "../atif/test-fixtures";
import {
  exportTrajectoryBundle,
  type TrajectoryExportInput,
} from "./trajectoryExport";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "apex-trajectory-export-"));
  temporaryDirectories.push(root);
  const source = nativeSource({ id: `source-${randomUUID()}` });
  const sourcePath = join(root, "saved-evidence.json");
  await writeFile(sourcePath, source.bytes);
  const outputDirectory = join(root, "trajectory-bundle");
  const input: TrajectoryExportInput = {
    sources: [
      {
        id: source.id,
        path: sourcePath,
        sha256: source.sha256,
        sizeBytes: source.sizeBytes,
      },
    ],
    rootSourceId: source.id,
    agent: { name: "apex", version: "test" },
    exporter: { name: "apex-native-evidence", version: "1" },
    outputDirectory,
  };
  return {
    root,
    source,
    sourcePath,
    outputDirectory,
    input,
    sourceInput: input.sources[0],
  };
}

async function exists(path: string): Promise<boolean> {
  return lstat(path).then(
    () => true,
    () => false,
  );
}

describe("exportTrajectoryBundle", () => {
  it("publishes exact validated files with the manifest as the commit marker", async () => {
    const { source, outputDirectory, input } = await fixture();

    const result = await exportTrajectoryBundle(input);

    expect(result.outputDirectory).toBe(outputDirectory);
    expect(result.manifestPath).toBe(
      join(outputDirectory, "trajectory-bundle.json"),
    );
    expect(result.manifest.validation.status).toBe("valid");
    expect(result.manifest.sources).toEqual([
      expect.objectContaining({ id: source.id, sha256: source.sha256 }),
    ]);
    for (const file of result.files) {
      const bytes = await readFile(
        join(outputDirectory, ...file.path.split("/")),
      );
      expect(bytes.byteLength).toBe(file.sizeBytes);
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(
        file.sha256,
      );
    }
    expect(JSON.parse(await readFile(result.manifestPath, "utf8"))).toEqual(
      result.manifest,
    );
  });

  it("rejects changed identities and malformed evidence before creating output", async () => {
    const { input, outputDirectory, sourceInput, sourcePath } = await fixture();
    await expect(
      exportTrajectoryBundle({
        ...input,
        sources: [{ ...sourceInput, sha256: "0".repeat(64) }],
      }),
    ).rejects.toMatchObject({ code: "SOURCE_IDENTITY_MISMATCH" });
    expect(await exists(outputDirectory)).toBe(false);

    const malformed = Buffer.from("{}\n");
    await writeFile(sourcePath, malformed);
    await expect(
      exportTrajectoryBundle({
        ...input,
        sources: [
          {
            ...sourceInput,
            sizeBytes: malformed.byteLength,
            sha256: createHash("sha256").update(malformed).digest("hex"),
          },
        ],
      }),
    ).rejects.toThrow("recorded evidence source validation failed");
    expect(await exists(outputDirectory)).toBe(false);
  });

  it("bounds reads and rejects symlinks before publishing", async () => {
    const { root, input, outputDirectory, sourceInput, sourcePath } =
      await fixture();
    await expect(
      exportTrajectoryBundle({
        ...input,
        sources: [
          {
            ...sourceInput,
            sizeBytes: 64 * 1024 * 1024 + 1,
          },
        ],
      }),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });

    const linked = join(root, "linked-evidence.json");
    await symlink(sourcePath, linked);
    await expect(
      exportTrajectoryBundle({
        ...input,
        sources: [{ ...sourceInput, path: linked }],
      }),
    ).rejects.toMatchObject({ code: "SOURCE_UNAVAILABLE" });
    expect(await exists(outputDirectory)).toBe(false);
  });

  it("does not publish a bundle whose independent validation failed", async () => {
    const { input, outputDirectory } = await fixture();

    await expect(
      exportTrajectoryBundle({
        ...input,
        independentValidation: {
          status: "failed",
          detail: "independent fixture rejected the document",
        },
      }),
    ).rejects.toMatchObject({ code: "BUNDLE_VALIDATION_FAILED" });
    expect(await exists(outputDirectory)).toBe(false);
  });

  it("never overwrites an existing destination", async () => {
    const { input, outputDirectory } = await fixture();
    await mkdir(outputDirectory);
    const sentinel = join(outputDirectory, "sentinel.txt");
    await writeFile(sentinel, "keep");

    await expect(exportTrajectoryBundle(input)).rejects.toMatchObject({
      code: "DESTINATION_EXISTS",
    });
    expect(await readFile(sentinel, "utf8")).toBe("keep");
    expect(await exists(join(outputDirectory, "trajectory-bundle.json"))).toBe(
      false,
    );
  });

  it("allows only one concurrent publisher for a fresh destination", async () => {
    const { input, outputDirectory } = await fixture();

    const results = await Promise.allSettled([
      exportTrajectoryBundle(input),
      exportTrajectoryBundle(input),
    ]);

    expect(
      results.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    const rejected = results.find((result) => result.status === "rejected");
    expect(rejected).toMatchObject({
      reason: expect.objectContaining({ code: "DESTINATION_EXISTS" }),
    });
    expect(await exists(join(outputDirectory, "trajectory-bundle.json"))).toBe(
      true,
    );
    expect((await readdir(outputDirectory)).length).toBeGreaterThan(1);
  });
});
