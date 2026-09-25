import { describe, expect, it, vi } from "vitest";
import { encodeCompactionEvidence } from "./compactionEvidence";

describe("bounded compaction evidence", () => {
  it("matches JSON for text, escaping, arrays and absent optional fields", () => {
    const value = {
      text: 'hello\n"world" 🐴',
      absent: undefined,
      parts: [null, true, 2, { output: "🐴" }],
    };
    const json = JSON.stringify(value);
    expect(encodeCompactionEvidence(value, Buffer.byteLength(json))).toEqual({
      status: "available",
      json,
      bytes: Buffer.byteLength(json),
    });
    expect(
      encodeCompactionEvidence(value, Buffer.byteLength(json) - 1),
    ).toMatchObject({ status: "truncated", reason: "byte_limit", bytes: 0 });
  });

  it("bounds wide and deep traversal without invoking getters or custom serializers", () => {
    expect(
      encodeCompactionEvidence(
        Array.from({ length: 20_000 }, () => 0),
        1_000_000,
      ),
    ).toMatchObject({ status: "truncated", reason: "structure_limit" });
    let deep: unknown = "end";
    for (let i = 0; i < 40; i++) deep = { nested: deep };
    expect(encodeCompactionEvidence(deep, 10_000)).toMatchObject({
      status: "truncated",
      reason: "structure_limit",
    });
    const getter = vi.fn();
    const value = Object.defineProperty({}, "secret", {
      enumerable: true,
      get: getter,
    });
    expect(encodeCompactionEvidence(value, 100)).toMatchObject({
      status: "unavailable",
      reason: "unsupported_value",
    });
    expect(getter).not.toHaveBeenCalled();
    const toJSON = vi.fn();
    expect(encodeCompactionEvidence({ toJSON }, 100)).toMatchObject({
      status: "unavailable",
      reason: "unsupported_value",
    });
    expect(toJSON).not.toHaveBeenCalled();
  });
});
