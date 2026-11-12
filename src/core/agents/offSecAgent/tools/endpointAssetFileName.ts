import { createHash } from "node:crypto";

// Linux caps a path component at 255 bytes; the headroom covers temp-file suffixes.
export const MAX_ASSET_FILE_NAME_BYTES = 200;

// The hash keeps truncated names distinct; the path prefix keeps them readable.
export function endpointAssetFileName(
  appName: string,
  routePath: string,
  tag?: string,
): string {
  const hash = createHash("sha256")
    .update(`${appName}__${routePath}`.toLowerCase())
    .digest("hex")
    .slice(0, 8);
  const prefix = "asset_";
  const suffix = `_${hash}${tag ? `_${tag}` : ""}.json`;
  if (tag !== undefined && !/^[A-Za-z0-9_-]+$/.test(tag))
    throw new Error(
      "Endpoint asset file name tag must be ASCII word characters",
    );
  const budget = MAX_ASSET_FILE_NAME_BYTES - prefix.length - suffix.length;
  if (budget < 1) throw new Error("Endpoint asset file name tag too long");
  // ASCII after sanitizing, so slicing characters slices bytes.
  const slug = routePath.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
  return `${prefix}${slug.slice(0, budget)}${suffix}`;
}
