import { describe, expect, it } from "vitest";
import {
  endpointAssetFileName,
  MAX_ASSET_FILE_NAME_BYTES,
} from "./endpointAssetFileName";

const longPath = `/api/v1/${Array.from({ length: 40 }, (_, i) => `listWidgets${i}`).join(",")}`;

describe("endpointAssetFileName", () => {
  it("keeps short names readable and unchanged in shape", () => {
    expect(endpointAssetFileName("Shop API", "/api/users/{id}")).toMatch(
      /^asset__api_users__id__[0-9a-f]{8}\.json$/,
    );
  });

  it("stays under the byte budget for a path far past NAME_MAX", () => {
    expect(longPath.length).toBeGreaterThan(255);
    for (const tag of [undefined, "existing", "2026-11-12T10-00-00-000Z"]) {
      const name = endpointAssetFileName("acme", longPath, tag);
      expect(Buffer.byteLength(name)).toBeLessThanOrEqual(
        MAX_ASSET_FILE_NAME_BYTES,
      );
      expect(name.startsWith("asset__api_v1_listwidgets0_listwidgets1")).toBe(
        true,
      );
      if (tag) expect(name.endsWith(`_${tag}.json`)).toBe(true);
    }
  });

  it("bounds bytes, not characters, for multibyte paths", () => {
    const name = endpointAssetFileName("acme", `/${"é".repeat(300)}`);
    expect(Buffer.byteLength(name)).toBeLessThanOrEqual(
      MAX_ASSET_FILE_NAME_BYTES,
    );
  });

  it("keeps long paths that share a truncated prefix distinct", () => {
    const a = endpointAssetFileName("acme", `${longPath},getA`, "existing");
    const b = endpointAssetFileName("acme", `${longPath},getB`, "existing");
    expect(a).not.toBe(b);
  });

  it("is stable for the same app and path", () => {
    expect(endpointAssetFileName("Acme", longPath)).toBe(
      endpointAssetFileName("acme", longPath),
    );
  });

  it("rejects a tag that could escape the directory or break the byte bound", () => {
    expect(() => endpointAssetFileName("acme", "/a", "../x")).toThrow();
    expect(() => endpointAssetFileName("acme", "/a", "é")).toThrow();
  });

  it("rejects a tag that leaves no room for the path", () => {
    expect(() => endpointAssetFileName("acme", "/a", "x".repeat(250))).toThrow(
      /too long/,
    );
  });
});
