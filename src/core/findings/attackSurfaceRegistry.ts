import { existsSync, readdirSync, readFileSync } from "fs";
import { join } from "path";

// ---------------------------------------------------------------------------
// Fingerprinting helpers
// ---------------------------------------------------------------------------

/**
 * Normalise a URL for comparison: lowercase, strip trailing slash,
 * strip query string, fragment, and protocol.
 */
function normalizeAssetUrl(url: string): string {
  let u = url.trim().toLowerCase();

  const hashIdx = u.indexOf("#");
  if (hashIdx !== -1) u = u.substring(0, hashIdx);

  const qIdx = u.indexOf("?");
  if (qIdx !== -1) u = u.substring(0, qIdx);

  u = u.replace(/^https?:\/\//, "");
  u = u.replace(/^www\./, "");

  if (u.length > 1 && u.endsWith("/")) {
    u = u.replace(/\/+$/, "");
  }

  return u;
}

/**
 * Normalise an asset name for comparison: lowercase, collapse
 * non-alphanumeric runs into a single dash, trim leading/trailing dashes.
 */
function normalizeAssetName(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

/**
 * Build fingerprint keys for an asset.
 *
 * - `urlKey`:  `[<app>||]<normalized_url>||<asset_type>` — precise per-URL dedup
 *              (only set when the asset has a URL)
 * - `nameKey`: `[<app>||]<normalized_name>||<asset_type>` — catches the same logical
 *              asset rediscovered with different metadata
 *
 * When `appName` is present, keys are scoped to that app so that
 * `/api/users` in App A and `/api/users` in App B are treated as
 * distinct assets.
 */
function generateAssetFingerprint(asset: AssetRecord): {
  urlKey: string | null;
  nameKey: string;
} {
  const normalizedName = normalizeAssetName(asset.assetName);
  const assetType = asset.assetType.toLowerCase();
  const url = asset.details?.url;
  const appPrefix = asset.appName
    ? `${normalizeAssetName(asset.appName)}||`
    : "";

  return {
    urlKey: url ? `${appPrefix}${normalizeAssetUrl(url)}||${assetType}` : null,
    nameKey: `${appPrefix}${normalizedName}||${assetType}`,
  };
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Minimal asset shape the registry needs for dedup.
 * Compatible with `DocumentedEndpointRecord` (persisted record)
 * and the inline records passed by `document_endpoint`.
 */
export interface AssetRecord {
  appName?: string;
  assetName: string;
  assetType: string;
  description: string;
  details?: {
    url?: string;
    [key: string]: unknown;
  };
  riskLevel?: string;
}

export interface AssetDuplicateCheckResult {
  duplicate: boolean;
  matchedAsset?: AssetRecord;
  matchType?: "exact-url" | "exact-name";
}

// ---------------------------------------------------------------------------
// AttackSurfaceRegistry
// ---------------------------------------------------------------------------

/**
 * Thread-safe, in-memory registry of known attack surface assets.
 *
 * Supports two dedup tiers:
 *   1. **Exact URL** — same normalised URL + same asset type
 *   2. **Exact name** — same normalised name + same asset type
 *
 * The registry is designed to be created once per session and shared
 * across concurrent attack surface agents via `ToolContext`.
 */
export class AttackSurfaceRegistry {
  private urlKeys = new Map<string, AssetRecord>();
  private nameKeys = new Map<string, AssetRecord>();
  private assets: AssetRecord[] = [];

  private mutex: Promise<void> = Promise.resolve();

  /** How many assets are tracked. */
  get size(): number {
    return this.assets.length;
  }

  /** Return a snapshot of all tracked assets. */
  getAssets(): readonly AssetRecord[] {
    return [...this.assets];
  }

  // -----------------------------------------------------------------------
  // Factories
  // -----------------------------------------------------------------------

  /**
   * Create a registry pre-loaded with assets from a directory.
   * Reads every `.json` file, parses each as an asset record, and indexes it.
   * Malformed files are silently skipped.
   */
  static fromDirectory(assetsPath: string): AttackSurfaceRegistry {
    const registry = new AttackSurfaceRegistry();

    if (!existsSync(assetsPath)) return registry;

    const files = readdirSync(assetsPath).filter((f) => f.endsWith(".json"));

    for (const file of files) {
      try {
        const raw = readFileSync(join(assetsPath, file), "utf-8");
        const asset = JSON.parse(raw) as AssetRecord;
        if (
          asset &&
          typeof asset.assetName === "string" &&
          typeof asset.assetType === "string"
        ) {
          registry.indexAsset(asset);
        }
      } catch {
        // skip malformed files
      }
    }

    return registry;
  }

  /**
   * Create a registry pre-loaded with an array of assets (e.g. from Console DB).
   */
  static fromAssets(assets: AssetRecord[]): AttackSurfaceRegistry {
    const registry = new AttackSurfaceRegistry();
    for (const a of assets) {
      registry.indexAsset(a);
    }
    return registry;
  }

  // -----------------------------------------------------------------------
  // Core API
  // -----------------------------------------------------------------------

  /**
   * Check whether an asset is a duplicate of something already registered.
   * Synchronous.
   *
   * Tier 1: exact URL + asset type
   * Tier 2: exact name + asset type
   */
  isDuplicate(asset: AssetRecord): AssetDuplicateCheckResult {
    const { urlKey, nameKey } = generateAssetFingerprint(asset);

    if (urlKey) {
      const urlMatch = this.urlKeys.get(urlKey);
      if (urlMatch) {
        return {
          duplicate: true,
          matchedAsset: urlMatch,
          matchType: "exact-url",
        };
      }
    }

    const nameMatch = this.nameKeys.get(nameKey);
    if (nameMatch) {
      return {
        duplicate: true,
        matchedAsset: nameMatch,
        matchType: "exact-name",
      };
    }

    return { duplicate: false };
  }

  /**
   * Register a new asset in the registry.
   *
   * Thread-safe via an async mutex. Returns the dedup check result.
   * If the asset is a duplicate it is **not** added to the registry.
   */
  async register(asset: AssetRecord): Promise<AssetDuplicateCheckResult> {
    return new Promise<AssetDuplicateCheckResult>((resolve) => {
      this.mutex = this.mutex.then(() => {
        const check = this.isDuplicate(asset);
        if (check.duplicate) {
          resolve(check);
        } else {
          this.indexAsset(asset);
          resolve({ duplicate: false });
        }
      });
    });
  }

  /**
   * Remove a previously-registered asset from all indexes.
   *
   * Rollback counterpart to {@link register}: call it when an asset was
   * accepted by the registry but the caller failed to persist it.
   */
  async unregister(asset: AssetRecord): Promise<void> {
    return new Promise<void>((resolve) => {
      this.mutex = this.mutex.then(() => {
        this.removeAsset(asset);
        resolve();
      });
    });
  }

  // -----------------------------------------------------------------------
  // Internal
  // -----------------------------------------------------------------------

  private removeAsset(asset: AssetRecord): void {
    const { urlKey, nameKey } = generateAssetFingerprint(asset);

    if (urlKey && this.urlKeys.get(urlKey) === asset) {
      this.urlKeys.delete(urlKey);
    }
    if (this.nameKeys.get(nameKey) === asset) {
      this.nameKeys.delete(nameKey);
    }

    const idx = this.assets.indexOf(asset);
    if (idx !== -1) {
      this.assets.splice(idx, 1);
    }
  }

  private indexAsset(asset: AssetRecord): void {
    const { urlKey, nameKey } = generateAssetFingerprint(asset);

    if (urlKey && !this.urlKeys.has(urlKey)) {
      this.urlKeys.set(urlKey, asset);
    }
    if (!this.nameKeys.has(nameKey)) {
      this.nameKeys.set(nameKey, asset);
    }

    this.assets.push(asset);
  }
}
