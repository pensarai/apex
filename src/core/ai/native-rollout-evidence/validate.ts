import { hashCanonicalJson, stringifyCanonicalJson } from "./content";
import type {
  ContentReferenceV1,
  EvidenceAvailability,
  NativeRolloutEvidenceEnvelopeV1,
} from "./schema";
import { NativeRolloutEvidenceEnvelopeSchema } from "./schema";

export type NativeRolloutEvidenceValidationCode =
  | "invalid-envelope"
  | "invalid-lineage"
  | "unresolved-content-reference"
  | "duplicate-content-reference"
  | "content-hash-mismatch"
  | "content-length-mismatch"
  | "misaligned-logprobs";

export class NativeRolloutEvidenceValidationError extends Error {
  readonly code: NativeRolloutEvidenceValidationCode;

  constructor(code: NativeRolloutEvidenceValidationCode, message: string) {
    super(message);
    this.name = "NativeRolloutEvidenceValidationError";
    this.code = code;
  }
}

function contentReferences(
  value: EvidenceAvailability<ContentReferenceV1>,
): ContentReferenceV1[] {
  if (value.state === "available") return [value.value];
  if (
    (value.state === "truncated" || value.state === "interrupted") &&
    value.partial
  ) {
    return [value.partial];
  }
  return [];
}

export function parseNativeRolloutEvidence(
  value: unknown,
): NativeRolloutEvidenceEnvelopeV1 {
  const parsed = NativeRolloutEvidenceEnvelopeSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const path = issue?.path.length ? issue.path.join(".") : "envelope";
    throw new NativeRolloutEvidenceValidationError(
      "invalid-envelope",
      `${path}: ${issue?.message ?? "invalid envelope"}`,
    );
  }

  const envelope = parsed.data;
  const { attempt } = envelope;
  if (
    (attempt.sequence === 1 && attempt.previousAttemptId !== undefined) ||
    (attempt.sequence > 1 && attempt.previousAttemptId === undefined) ||
    (attempt.sequence === 1 && attempt.rootAttemptId !== attempt.attemptId)
  ) {
    throw new NativeRolloutEvidenceValidationError(
      "invalid-lineage",
      "attempt sequence, rootAttemptId, and previousAttemptId disagree",
    );
  }

  const assetsByRef = new Map<
    string,
    NativeRolloutEvidenceEnvelopeV1["assets"][number]
  >();
  for (const asset of envelope.assets) {
    if (assetsByRef.has(asset.ref)) {
      throw new NativeRolloutEvidenceValidationError(
        "duplicate-content-reference",
        `asset ${asset.ref} is listed more than once`,
      );
    }
    const measured = hashCanonicalJson(asset.content);
    if (
      `sha256:${measured.sha256}` !== asset.ref ||
      measured.sha256 !== asset.sha256
    ) {
      throw new NativeRolloutEvidenceValidationError(
        "content-hash-mismatch",
        `asset ${asset.ref} does not match its canonical content hash`,
      );
    }
    if (measured.byteLength !== asset.byteLength) {
      throw new NativeRolloutEvidenceValidationError(
        "content-length-mismatch",
        `asset ${asset.ref} byteLength does not match canonical content`,
      );
    }
    assetsByRef.set(asset.ref, asset);
  }

  const references = [
    envelope.boundary.input.normalizedRef,
    ...contentReferences(envelope.boundary.input.native),
    ...contentReferences(envelope.boundary.output.normalized),
    ...contentReferences(envelope.boundary.output.native),
  ];
  for (const reference of references) {
    const asset = assetsByRef.get(reference.ref);
    if (!asset) {
      throw new NativeRolloutEvidenceValidationError(
        "unresolved-content-reference",
        `content reference ${reference.ref} has no asset`,
      );
    }
    if (
      asset.mediaType !== reference.mediaType ||
      asset.byteLength !== reference.byteLength
    ) {
      throw new NativeRolloutEvidenceValidationError(
        "content-length-mismatch",
        `content reference ${reference.ref} metadata disagrees with its asset`,
      );
    }
  }

  if (
    envelope.native.completionTokenIds.state === "available" &&
    envelope.native.logprobs.state === "available" &&
    envelope.native.completionTokenIds.value.length !==
      envelope.native.logprobs.value.length
  ) {
    throw new NativeRolloutEvidenceValidationError(
      "misaligned-logprobs",
      "completionTokenIds and logprobs must have identical lengths",
    );
  }

  return envelope;
}

export function serializeNativeRolloutEvidence(
  envelope: NativeRolloutEvidenceEnvelopeV1,
): string {
  return stringifyCanonicalJson(parseNativeRolloutEvidence(envelope));
}
