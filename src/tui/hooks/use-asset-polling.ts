/**
 * useAssetPolling Hook
 *
 * Polls the filesystem for discovered asset JSON files within a session's
 * assets directory. Returns the parsed asset list and a derived count.
 * Cleans up the polling interval on unmount or when the session changes.
 */

import { useState, useEffect } from "react";
import { existsSync, readdirSync, readFileSync } from "fs";
import { join } from "path";
import type { SessionInfo } from "../../core/session";
import type { DocumentedAssetRecord } from "../../core/agents/specialized/attackSurface/schemas";

const POLL_INTERVAL_MS = 2000;

export interface UseAssetPollingReturn {
  /** Parsed asset records from the session's assets directory. */
  assets: DocumentedAssetRecord[];
  /** Number of discovered assets. */
  assetCount: number;
}

/**
 * Poll the session's assets directory for discovered asset JSON files.
 *
 * Returns an empty list when session is null. Begins polling once a valid
 * session is provided, reading every {@link POLL_INTERVAL_MS} ms.
 */
export function useAssetPolling(
  session: SessionInfo | null,
): UseAssetPollingReturn {
  const [assets, setAssets] = useState<DocumentedAssetRecord[]>([]);

  useEffect(() => {
    if (!session) return;
    const assetsPath = join(session.rootPath, "assets");

    function readAssets() {
      if (!existsSync(assetsPath)) return;
      try {
        const files = readdirSync(assetsPath).filter((f) =>
          f.endsWith(".json"),
        );
        const loaded: DocumentedAssetRecord[] = [];
        for (const file of files) {
          try {
            const content = readFileSync(join(assetsPath, file), "utf-8");
            loaded.push(JSON.parse(content));
          } catch {
            // skip malformed files
          }
        }
        setAssets(loaded);
      } catch {
        // assets dir may not exist yet
      }
    }

    readAssets();
    const interval = setInterval(readAssets, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [session]);

  return { assets, assetCount: assets.length };
}
