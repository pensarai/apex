import {
  getAllowedHosts,
  isHostAllowed,
} from "../agents/offSecAgent/tools/scopeGuard";
import type { ToolContext } from "../agents/offSecAgent/tools/types";
import type { HarEntry } from "./types";

function filterHarEntriesByAllowedHosts(
  entries: HarEntry[],
  allowedHosts: string[],
): HarEntry[] {
  if (allowedHosts.length === 0) return entries;

  return entries.filter((entry) => {
    try {
      const hostname = new URL(entry.request.url).hostname.toLowerCase();
      return isHostAllowed(hostname, allowedHosts);
    } catch {
      return false;
    }
  });
}

export function filterHarByScope(
  entries: HarEntry[],
  ctx: ToolContext,
): HarEntry[] {
  return filterHarEntriesByAllowedHosts(entries, getAllowedHosts(ctx));
}
