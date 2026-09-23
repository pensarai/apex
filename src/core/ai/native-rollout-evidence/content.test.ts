import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createContentAddressedAsset,
  hashCanonicalJson,
  stringifyCanonicalJson,
  toJsonValue,
} from "./content";

describe("native rollout evidence content", () => {
  it("preserves own prototype-shaped keys through canonical bytes and hashing", () => {
    const input = JSON.parse(
      '{"__proto__":{"marker":true},"constructor":{"prototype":"own"},"nested":{"__proto__":{"depth":2},"constructor":"nested"}}',
    ) as unknown;

    const normalized = toJsonValue(input);
    expect(Object.getPrototypeOf(normalized)).toBeNull();
    expect(Object.hasOwn(normalized as object, "__proto__")).toBe(true);
    expect(Object.hasOwn(normalized as object, "constructor")).toBe(true);

    const nested = (normalized as Record<string, unknown>).nested;
    expect(Object.getPrototypeOf(nested)).toBeNull();
    expect(Object.hasOwn(nested as object, "__proto__")).toBe(true);
    expect(Object.hasOwn(nested as object, "constructor")).toBe(true);

    const canonical = stringifyCanonicalJson(normalized);
    const reparsed = JSON.parse(canonical) as Record<string, unknown>;
    expect(reparsed.__proto__).toEqual({ marker: true });
    expect(reparsed.constructor).toEqual({ prototype: "own" });
    expect(reparsed.nested).toEqual(
      JSON.parse('{"__proto__":{"depth":2},"constructor":"nested"}'),
    );
    expect(Object.hasOwn(reparsed, "__proto__")).toBe(true);
    expect(Object.hasOwn(reparsed.nested as object, "__proto__")).toBe(true);

    const bytes = Buffer.from(canonical);
    const expectedSha256 = createHash("sha256").update(bytes).digest("hex");
    expect(hashCanonicalJson(normalized)).toEqual({
      sha256: expectedSha256,
      byteLength: bytes.byteLength,
    });
    expect(
      createContentAddressedAsset(normalized, "prototype-key-fixture"),
    ).toEqual(
      expect.objectContaining({
        asset: expect.objectContaining({
          ref: `sha256:${expectedSha256}`,
          sha256: expectedSha256,
          byteLength: bytes.byteLength,
          content: normalized,
        }),
      }),
    );
  });
});
