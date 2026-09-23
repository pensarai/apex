import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { posix } from "node:path";
import { describe, expect, it } from "vitest";
import type { AtifConversionError } from "./convert";
import type { AtifBundleFile, ConvertNativeRolloutToAtifInput } from "./schema";
import { TRAJECTORY_BUNDLE_FILENAME, TRAJECTORY_BUNDLE_LIMITS } from "./schema";
import { serializeAtifExportBundle } from "./serialize";
import { nativeSource } from "./test-fixtures";

interface CompatibilityFixture {
  fixtureVersion: 1;
  profile: {
    manifestFilename: string;
    limits: typeof TRAJECTORY_BUNDLE_LIMITS;
  };
  request: Omit<ConvertNativeRolloutToAtifInput, "sources"> & {
    sources: Array<{
      id: string;
      path: string;
      sha256: string;
      sizeBytes: number;
    }>;
  };
  files: Array<Omit<AtifBundleFile, "bytes"> & { contentBase64: string }>;
}

const fixture = JSON.parse(
  readFileSync(
    new URL("./fixtures/portable-bundle-v1.json", import.meta.url),
    "utf8",
  ),
) as CompatibilityFixture;

describe("portable bundle v1 compatibility", () => {
  it("reproduces the shared consumer fixture from its exact saved source bytes", () => {
    const recorded = new Map(fixture.files.map((file) => [file.path, file]));
    const bytesAt = (path: string) => {
      const file = recorded.get(path);
      if (!file) throw new Error(`Missing compatibility fixture file: ${path}`);
      return Buffer.from(file.contentBase64, "base64");
    };
    const bundle = serializeAtifExportBundle({
      ...fixture.request,
      sources: fixture.request.sources.map((source) => ({
        id: source.id,
        sha256: source.sha256,
        sizeBytes: source.sizeBytes,
        bytes: bytesAt(source.path),
      })),
    });

    expect(fixture.fixtureVersion).toBe(1);
    expect(fixture.profile.manifestFilename).toBe(TRAJECTORY_BUNDLE_FILENAME);
    expect(fixture.profile.limits).toEqual(TRAJECTORY_BUNDLE_LIMITS);
    expect(bundle.files.length).toBeGreaterThan(64);
    expect(
      bundle.files.map(({ bytes, ...file }) => ({
        ...file,
        contentBase64: Buffer.from(bytes).toString("base64"),
      })),
    ).toEqual(fixture.files);
    for (const file of bundle.files) {
      expect(file.bytes.byteLength).toBe(file.sizeBytes);
      expect(createHash("sha256").update(file.bytes).digest("hex")).toBe(
        file.sha256,
      );
    }
    const paths = new Set(bundle.files.map((file) => file.path));
    for (const document of bundle.manifest.documents) {
      const trajectory = JSON.parse(bytesAt(document.path).toString("utf8"));
      if (trajectory.continued_trajectory_ref) {
        expect(
          paths.has(
            posix.join(
              posix.dirname(document.path),
              trajectory.continued_trajectory_ref,
            ),
          ),
        ).toBe(true);
      }
    }
    expect(bundle.manifest.validation.independent.status).toBe("not_run");
    expect(bundle.manifest.completeness.sftEligibility).toBe("ineligible");
  });

  it("rejects a source collection whose complete file set exceeds the shared budget", () => {
    const sources = Array.from({ length: 256 }, (_, index) =>
      nativeSource({
        id: `source-${index}`,
        attemptId: `atm_${index}`,
        turnIndex: index + 1,
      }),
    );
    expect(() =>
      serializeAtifExportBundle({
        ...fixture.request,
        rootSourceId: sources[0].id,
        sources,
      }),
    ).toThrowError(
      expect.objectContaining<Partial<AtifConversionError>>({
        diagnostics: [expect.objectContaining({ code: "bundle_size_limit" })],
      }),
    );
  });
});
