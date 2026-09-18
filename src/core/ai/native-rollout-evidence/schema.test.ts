import { describe, expect, it } from "vitest";
import type { AttemptID, IdempotencyKey } from "../../id/id";
import {
  createContentAddressedAsset,
  hashCanonicalJson,
  toJsonValue,
} from "./content";
import type { NativeRolloutEvidenceEnvelopeV1 } from "./schema";
import {
  JsonValueSchema,
  NATIVE_ROLLOUT_EVIDENCE_SCHEMA,
  NATIVE_ROLLOUT_EVIDENCE_VERSION,
} from "./schema";
import {
  type NativeRolloutEvidenceValidationError,
  parseNativeRolloutEvidence,
  serializeNativeRolloutEvidence,
} from "./validate";

function fixture(): NativeRolloutEvidenceEnvelopeV1 {
  const input = createContentAddressedAsset(
    { prompt: "hello" },
    "ai-sdk-v3-call-options",
  );
  const output = createContentAddressedAsset(
    { text: "world" },
    "ai-sdk-v3-output",
  );
  return {
    schema: NATIVE_ROLLOUT_EVIDENCE_SCHEMA,
    version: NATIVE_ROLLOUT_EVIDENCE_VERSION,
    runId: "run_test",
    sessionId: "ses_test",
    segmentId: "segment_000001",
    turnId: "turn_000001",
    turnIndex: 1,
    operationKind: "agent.stream",
    attempt: {
      attemptId: "atm_first" as AttemptID,
      idempotencyKey: "idem_first" as IdempotencyKey,
      sequence: 1,
      rootAttemptId: "atm_first" as AttemptID,
      lifecycle: "completed",
    },
    requested: { provider: "openai", modelId: "requested" },
    effective: { provider: "openai", modelId: "effective" },
    boundary: {
      input: {
        normalizedRef: input.reference,
        native: { state: "omitted", reason: "not exposed" },
      },
      output: {
        normalized: { state: "available", value: output.reference },
        native: { state: "omitted", reason: "not exposed" },
      },
    },
    native: {
      promptTokenIds: { state: "available", value: [10, 20] },
      completionTokenIds: { state: "available", value: [30, 40] },
      logprobs: { state: "available", value: [0, -1.25] },
      tokenizer: { state: "available", value: { name: "test-tokenizer" } },
      extra: { state: "omitted", reason: "not exposed" },
    },
    assets: [input.asset, output.asset],
    limitations: [],
  };
}

describe("native rollout evidence schema", () => {
  it("preserves empty sequences and zero log probabilities", () => {
    const value = fixture();
    value.native.promptTokenIds = { state: "available", value: [] };
    value.native.completionTokenIds = { state: "available", value: [30] };
    value.native.logprobs = { state: "available", value: [0] };

    const parsed = parseNativeRolloutEvidence(value);
    expect(parsed.native.promptTokenIds).toEqual({
      state: "available",
      value: [],
    });
    expect(parsed.native.logprobs).toEqual({
      state: "available",
      value: [0],
    });
  });

  it("rejects shifted token and probability arrays", () => {
    const value = fixture();
    value.native.logprobs = { state: "available", value: [-0.5] };

    expect(() => parseNativeRolloutEvidence(value)).toThrowError(
      expect.objectContaining<Partial<NativeRolloutEvidenceValidationError>>({
        code: "misaligned-logprobs",
      }),
    );
  });

  it("rejects unresolved content references", () => {
    const value = fixture();
    value.assets = value.assets.slice(0, 1);

    expect(() => parseNativeRolloutEvidence(value)).toThrowError(
      expect.objectContaining<Partial<NativeRolloutEvidenceValidationError>>({
        code: "unresolved-content-reference",
      }),
    );
  });

  it("rejects content whose canonical hash was changed", () => {
    const value = fixture();
    value.assets[0].content = { prompt: "changed" };

    expect(() => parseNativeRolloutEvidence(value)).toThrowError(
      expect.objectContaining<Partial<NativeRolloutEvidenceValidationError>>({
        code: "content-hash-mismatch",
      }),
    );
  });

  it("rejects contradictory retry lineage", () => {
    const value = fixture();
    value.attempt.sequence = 2;

    expect(() => parseNativeRolloutEvidence(value)).toThrowError(
      expect.objectContaining<Partial<NativeRolloutEvidenceValidationError>>({
        code: "invalid-lineage",
      }),
    );
  });

  it("rejects non-JSON values, cycles, sparse arrays, and excessive depth", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    const sparse: unknown[] = [];
    sparse.length = 1;
    let tooDeep: unknown = null;
    for (let depth = 0; depth < 66; depth++) {
      tooDeep = { next: tooDeep };
    }

    for (const value of [
      Number.NaN,
      { missing: undefined },
      new Date("2026-01-01T00:00:00.000Z"),
      sparse,
      cyclic,
      tooDeep,
    ]) {
      expect(JsonValueSchema.safeParse(value).success).toBe(false);
    }
  });

  it("serializes equivalent objects deterministically", () => {
    const first = fixture();
    const second = fixture();
    second.assets[0].content = { prompt: "hello" };

    expect(serializeNativeRolloutEvidence(first)).toBe(
      serializeNativeRolloutEvidence(second),
    );
  });

  it("preserves prototype-shaped own keys through evidence serialization", () => {
    const specialContent = toJsonValue(
      JSON.parse(
        '{"__proto__":{"marker":true},"constructor":{"prototype":"own"},"nested":{"__proto__":{"depth":2},"constructor":"nested"}}',
      ),
    );
    const specialAsset = createContentAddressedAsset(
      specialContent,
      "prototype-key-fixture",
    );
    const value = fixture();
    value.boundary.input.normalizedRef = specialAsset.reference;
    value.assets[0] = specialAsset.asset;

    const serialized = serializeNativeRolloutEvidence(value);
    const parsed = parseNativeRolloutEvidence(JSON.parse(serialized));
    const content = parsed.assets[0].content as Record<string, unknown>;
    const nested = content.nested as Record<string, unknown>;

    expect(content).not.toBe(specialContent);
    expect(Object.getPrototypeOf(content)).toBeNull();
    expect(Object.getPrototypeOf(nested)).toBeNull();
    expect(Object.hasOwn(content, "__proto__")).toBe(true);
    expect(Object.hasOwn(content, "constructor")).toBe(true);
    expect(Object.hasOwn(nested, "__proto__")).toBe(true);
    expect(Object.hasOwn(nested, "constructor")).toBe(true);
    expect(hashCanonicalJson(parsed.assets[0].content)).toEqual(
      hashCanonicalJson(specialContent),
    );
    expect(serializeNativeRolloutEvidence(parsed)).toBe(serialized);
  });
});
