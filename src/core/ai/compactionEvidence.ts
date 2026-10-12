const MAX_NODES = 10_000;
const MAX_DEPTH = 32;

export const CONTEXT_EVIDENCE_BYTES = 2 * 1024 * 1024;
export const RESULT_EVIDENCE_BYTES = 256 * 1024;
export const MAX_RESULT_EVIDENCE = 256;

export type EvidenceStatus =
  | "available"
  | "truncated"
  | "unavailable"
  | "failed";

class EvidenceLimit extends Error {
  constructor(
    readonly status: EvidenceStatus,
    readonly reason: string,
  ) {
    super(reason);
  }
}

// Bound traversal and allocations before serialization, including huge strings.
export function encodeCompactionEvidence(value: unknown, maxBytes: number) {
  const chunks: string[] = [];
  const ancestors = new Set<object>();
  let bytes = 0;
  let nodes = 0;
  const append = (text: string) => {
    bytes += Buffer.byteLength(text);
    if (bytes > maxBytes) throw new EvidenceLimit("truncated", "byte_limit");
    chunks.push(text);
  };
  const string = (text: string) => {
    if (text.length > maxBytes - bytes)
      throw new EvidenceLimit("truncated", "byte_limit");
    append(JSON.stringify(text));
  };
  const visit = (item: unknown, depth: number): void => {
    if (++nodes > MAX_NODES || depth > MAX_DEPTH)
      throw new EvidenceLimit("truncated", "structure_limit");
    if (typeof item === "string") {
      string(item);
      return;
    }
    if (
      item === null ||
      typeof item === "boolean" ||
      typeof item === "number"
    ) {
      append(JSON.stringify(item));
      return;
    }
    if (typeof item !== "object" || ancestors.has(item))
      throw new EvidenceLimit("unavailable", "unsupported_value");
    const array = Array.isArray(item);
    const prototype = Object.getPrototypeOf(item);
    if (!array && prototype !== Object.prototype && prototype !== null)
      throw new EvidenceLimit("unavailable", "unsupported_value");
    ancestors.add(item);
    append(array ? "[" : "{");
    let count = 0;
    const property = (key: string) => {
      if (++nodes > MAX_NODES)
        throw new EvidenceLimit("truncated", "structure_limit");
      const descriptor = Object.getOwnPropertyDescriptor(item, key);
      if (!descriptor || !("value" in descriptor))
        throw new EvidenceLimit("unavailable", "unsupported_value");
      if (!array && descriptor.value === undefined) return;
      if (count++) append(",");
      if (!array) {
        string(key);
        append(":");
      }
      visit(
        descriptor.value === undefined ? null : descriptor.value,
        depth + 1,
      );
    };
    if (array) {
      for (let i = 0; i < item.length; i++) property(String(i));
    } else {
      for (const key in item) {
        if (Object.hasOwn(item, key)) property(key);
      }
    }
    append(array ? "]" : "}");
    ancestors.delete(item);
  };
  try {
    visit(value, 0);
    return { status: "available" as const, json: chunks.join(""), bytes };
  } catch (error) {
    return {
      status: error instanceof EvidenceLimit ? error.status : "failed",
      reason:
        error instanceof EvidenceLimit ? error.reason : "serialization_failed",
      bytes: 0,
    };
  }
}
