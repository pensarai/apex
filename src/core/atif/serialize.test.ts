import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { AtifConversionError } from "./convert";
import {
  ATIF_REFERENCE_REVISION,
  ATIF_SCHEMA_VERSION,
  TRAJECTORY_BUNDLE_TYPE,
  TrajectoryBundleManifestSchema,
} from "./schema";
import { serializeAtifExportBundle } from "./serialize";
import { nativeSource } from "./test-fixtures";

const identity = {
  agent: { name: "apex", version: "test" },
  exporter: { name: "apex-native-evidence", version: "1" },
};

function hash(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

describe("neutral Evalgate trajectory bundle serialization", () => {
  it("emits an immutable manifest plus individual ATIF, asset, and source files", () => {
    const source = nativeSource();
    const bundle = serializeAtifExportBundle({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });

    expect(TrajectoryBundleManifestSchema.parse(bundle.manifest)).toMatchObject(
      {
        type: TRAJECTORY_BUNDLE_TYPE,
        version: 1,
        rootTrajectoryId: "atif_atm_fixture_001",
        atif: {
          schemaVersion: ATIF_SCHEMA_VERSION,
          referenceRevision: ATIF_REFERENCE_REVISION,
        },
        validation: {
          status: "passed",
          independent: { status: "not_run" },
        },
        completeness: {
          transcript: "complete",
          sftEligibility: "ineligible",
          rlEligibility: "ineligible",
        },
      },
    );
    expect(bundle.manifest.documents).toHaveLength(1);
    expect(bundle.manifest.sources).toEqual([
      {
        id: source.id,
        path: `sources/${source.id}.json`,
        sha256: source.sha256,
        sizeBytes: source.sizeBytes,
      },
    ]);
    expect(bundle.files.map((file) => file.kind)).toEqual([
      "asset",
      "asset",
      "manifest",
      "source",
      "document",
    ]);
    for (const file of bundle.files) {
      expect(file.sha256).toBe(hash(file.bytes));
      expect(file.sizeBytes).toBe(file.bytes.byteLength);
    }
    const sourceFile = bundle.files.find((file) => file.kind === "source");
    expect(sourceFile?.bytes).toEqual(source.bytes);
  });

  it("is byte-deterministic when input sources arrive in another order", () => {
    const first = nativeSource({ id: "first", attemptId: "atm_first" });
    const second = nativeSource({
      id: "second",
      attemptId: "atm_second",
      idempotencyKey: "idem_second",
      turnIndex: 2,
    });
    const input = { ...identity, rootSourceId: first.id };

    const left = serializeAtifExportBundle({
      ...input,
      sources: [first, second],
    });
    const right = serializeAtifExportBundle({
      ...input,
      sources: [second, first],
    });

    expect(
      left.files.map((file) => [file.path, file.sha256, file.sizeBytes]),
    ).toEqual(
      right.files.map((file) => [file.path, file.sha256, file.sizeBytes]),
    );
    expect(left.files.map((file) => file.bytes)).toEqual(
      right.files.map((file) => file.bytes),
    );
  });

  it("reports a failed attempt and missing output as a partial transcript", () => {
    const source = nativeSource({
      lifecycle: "failed",
      outputAvailable: false,
    });

    const bundle = serializeAtifExportBundle({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });

    expect(bundle.manifest.validation.status).toBe("passed");
    expect(bundle.manifest.completeness.transcript).toBe("partial");
    expect(
      bundle.manifest.completeness.diagnostics.map((entry) => entry.code),
    ).toEqual(
      expect.arrayContaining([
        "incomplete_attempt_lifecycle",
        "missing_output",
      ]),
    );
  });

  it("rejects source bytes that do not match their immutable identity", () => {
    const source = nativeSource();
    source.sha256 = "0".repeat(64);

    expect(() =>
      serializeAtifExportBundle({
        ...identity,
        sources: [source],
        rootSourceId: source.id,
      }),
    ).toThrowError(
      expect.objectContaining<Partial<AtifConversionError>>({
        name: "AtifConversionError",
        diagnostics: [
          expect.objectContaining({ code: "source_identity_mismatch" }),
        ],
      }),
    );
  });

  it("rejects an unbounded source collection before parsing content", () => {
    const source = nativeSource();

    expect(() =>
      serializeAtifExportBundle({
        ...identity,
        sources: Array.from({ length: 513 }, () => source),
        rootSourceId: source.id,
      }),
    ).toThrowError(
      expect.objectContaining<Partial<AtifConversionError>>({
        diagnostics: [expect.objectContaining({ code: "source_count_limit" })],
      }),
    );
  });

  it("rejects an attempt identity that could escape the trajectories directory", () => {
    const source = nativeSource({ attemptId: "atm_../../manifest" });

    expect(() =>
      serializeAtifExportBundle({
        ...identity,
        sources: [source],
        rootSourceId: source.id,
      }),
    ).toThrowError(
      expect.objectContaining<Partial<AtifConversionError>>({
        diagnostics: [
          expect.objectContaining({ code: "invalid_attempt_path_identity" }),
        ],
      }),
    );
  });

  it("treats unusual session identifiers as data rather than object keys", () => {
    const source = nativeSource({ sessionId: "__proto__" });
    const bundle = serializeAtifExportBundle({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });

    expect(bundle.documents.__proto__).toHaveLength(1);
    expect(bundle.manifest.documents).toHaveLength(1);
  });

  it("retains an independently supplied validator result separately", () => {
    const source = nativeSource();
    const bundle = serializeAtifExportBundle({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
      independentValidation: {
        status: "passed",
        detail: "validated by the injected offline reference validator",
      },
    });

    expect(bundle.manifest.validation).toMatchObject({
      status: "passed",
      independent: {
        status: "passed",
        detail: "validated by the injected offline reference validator",
      },
    });
  });

  it("retains exposed native request and response bodies as hashed assets", () => {
    const source = nativeSource({
      nativeInput: { request: "synthetic" },
      nativeOutput: { response: "synthetic" },
    });
    const bundle = serializeAtifExportBundle({
      ...identity,
      sources: [source],
      rootSourceId: source.id,
    });

    expect(bundle.manifest.assets).toHaveLength(4);
    const root = bundle.documents.ses_fixture?.[0];
    expect(root?.extra).toMatchObject({
      boundary: {
        input: { native: { state: "available", ref: expect.any(String) } },
        output: { native: { state: "available", ref: expect.any(String) } },
      },
    });
  });
});
