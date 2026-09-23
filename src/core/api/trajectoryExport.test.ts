import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  type open,
  readdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { nativeSource } from "../atif/test-fixtures";
import {
  exportTrajectoryBundle,
  type TrajectoryExportInput,
} from "./trajectoryExport";

const fsMocks = vi.hoisted(() => ({
  open: vi.fn(),
  realOpen: undefined as typeof open | undefined,
}));
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  fsMocks.realOpen = actual.open;
  fsMocks.open.mockImplementation(actual.open);
  return { ...actual, open: fsMocks.open };
});

const temporaryDirectories: string[] = [];

afterEach(async () => {
  if (fsMocks.realOpen) fsMocks.open.mockImplementation(fsMocks.realOpen);
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
  it.each([
    false,
    true,
  ])("keeps the final marker absent until a blocked manifest write succeeds (failure: %s)", async (fail) => {
    const { input, outputDirectory } = await fixture();
    let release!: () => void;
    let started!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const writing = new Promise<void>((resolve) => {
      started = resolve;
    });
    const realOpen = fsMocks.realOpen;
    if (!realOpen) throw new Error("missing real fs.open implementation");
    fsMocks.open.mockImplementation(async (...args) => {
      const handle = await realOpen(args[0], args[1], args[2]);
      if (!String(args[0]).includes("trajectory-bundle.json")) return handle;
      return {
        close: handle.close.bind(handle),
        sync: handle.sync.bind(handle),
        writeFile: async (bytes: Uint8Array) => {
          await handle.writeFile(bytes.subarray(0, 8));
          started();
          await blocked;
          if (fail) throw new Error("interrupted manifest write");
          await handle.writeFile(bytes.subarray(8));
        },
      } as Awaited<ReturnType<typeof open>>;
    });
    const result = exportTrajectoryBundle(input);
    await writing;
    const visible = await exists(
      join(outputDirectory, "trajectory-bundle.json"),
    );
    release();
    if (fail)
      await expect(result).rejects.toMatchObject({ code: "PUBLISH_FAILED" });
    else await result;
    expect(visible).toBe(false);
    expect(await exists(join(outputDirectory, "trajectory-bundle.json"))).toBe(
      !fail,
    );
    if (!fail)
      expect(
        JSON.parse(
          await readFile(
            join(outputDirectory, "trajectory-bundle.json"),
            "utf8",
          ),
        ),
      ).toMatchObject({ rootTrajectoryId: "atif_atm_fixture_001" });
  });

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
