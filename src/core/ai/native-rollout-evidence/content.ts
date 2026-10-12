import { createHash } from "node:crypto";
import type {
  ContentAddressedAssetV1,
  ContentReferenceV1,
  JsonValue,
} from "./schema";

export class NativeRolloutContentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NativeRolloutContentError";
  }
}

export function toJsonValue(value: unknown): JsonValue {
  return normalizeJsonValue(value, new WeakSet<object>(), 0);
}

function normalizeJsonValue(
  value: unknown,
  ancestors: WeakSet<object>,
  depth: number,
): JsonValue {
  if (depth > 64) {
    throw new NativeRolloutContentError("content nesting exceeds 64 levels");
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new NativeRolloutContentError(
        "content contains a non-finite number",
      );
    }
    return value;
  }
  if (typeof value === "bigint") {
    return { $type: "bigint", value: value.toString() };
  }
  if (value instanceof Date) {
    return { $type: "date", value: value.toISOString() };
  }
  if (value instanceof URL) {
    return { $type: "url", value: value.toString() };
  }
  if (value instanceof Uint8Array) {
    return {
      $type: "bytes",
      encoding: "base64",
      value: Buffer.from(value).toString("base64"),
    };
  }
  if (typeof value !== "object") {
    throw new NativeRolloutContentError(
      `content contains unsupported ${typeof value}`,
    );
  }
  if (ancestors.has(value)) {
    throw new NativeRolloutContentError("content contains a cycle");
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((entry) =>
        entry === undefined
          ? null
          : normalizeJsonValue(entry, ancestors, depth + 1),
      );
    }

    const normalized = Object.create(null) as Record<string, JsonValue>;
    for (const [key, entry] of Object.entries(value)) {
      if (entry === undefined) continue;
      normalized[key] = normalizeJsonValue(entry, ancestors, depth + 1);
    }
    return normalized;
  } finally {
    ancestors.delete(value);
  }
}

export function stringifyCanonicalJson(value: JsonValue): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stringifyCanonicalJson).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map(
      (key) =>
        `${JSON.stringify(key)}:${stringifyCanonicalJson(value[key] as JsonValue)}`,
    )
    .join(",")}}`;
}

export function hashCanonicalJson(value: JsonValue): {
  sha256: string;
  byteLength: number;
} {
  const encoded = Buffer.from(stringifyCanonicalJson(value));
  return {
    sha256: createHash("sha256").update(encoded).digest("hex"),
    byteLength: encoded.byteLength,
  };
}

export function createContentAddressedAsset(
  content: JsonValue,
  representation: string,
  mediaType = "application/json",
): {
  asset: ContentAddressedAssetV1;
  reference: ContentReferenceV1;
} {
  const { sha256, byteLength } = hashCanonicalJson(content);
  const ref = `sha256:${sha256}` as const;
  return {
    asset: { ref, sha256, mediaType, byteLength, content },
    reference: { ref, mediaType, byteLength, representation },
  };
}
