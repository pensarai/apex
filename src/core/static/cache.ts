/**
 * Static Analysis Cache Management
 *
 * Caches expensive artifacts like CodeQL databases and Joern CPGs
 * keyed by repository URL and commit SHA for reuse across runs.
 */

import os from 'os';
import path from 'path';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import type { AnalysisTool } from './types';

/**
 * Global cache directory for static analysis artifacts
 */
export function getGlobalCacheRoot(): string {
  return path.join(os.homedir(), '.pensar', 'static-cache');
}

/**
 * Cache entry metadata
 */
export interface CacheEntry {
  /** Cache key (repo hash + commit) */
  key: string;
  /** Type of cached artifact */
  type: 'codeql-db' | 'joern-cpg' | 'symbol-index';
  /** Path to cached artifact */
  path: string;
  /** Size in bytes */
  size: number;
  /** ISO timestamp of creation */
  created_at: string;
  /** ISO timestamp of last access */
  last_accessed: string;
  /** Number of times accessed */
  access_count: number;
  /** Languages covered (for CodeQL/Joern) */
  languages?: string[];
  /** Commit SHA */
  commit: string;
  /** Repository URL (if remote) */
  repo_url?: string;
}

/**
 * Cache manifest (index of all cached artifacts)
 */
export interface CacheManifest {
  version: number;
  entries: CacheEntry[];
  total_size: number;
  last_cleanup: string;
}

const CACHE_MANIFEST_VERSION = 1;
const MAX_CACHE_SIZE_BYTES = 10 * 1024 * 1024 * 1024; // 10 GB default

/**
 * Get cache manifest path
 */
function getManifestPath(): string {
  return path.join(getGlobalCacheRoot(), 'manifest.json');
}

/**
 * Load cache manifest
 */
export async function loadCacheManifest(): Promise<CacheManifest> {
  const manifestPath = getManifestPath();
  try {
    const content = await fs.readFile(manifestPath, 'utf-8');
    return JSON.parse(content) as CacheManifest;
  } catch {
    return {
      version: CACHE_MANIFEST_VERSION,
      entries: [],
      total_size: 0,
      last_cleanup: new Date().toISOString(),
    };
  }
}

/**
 * Save cache manifest
 */
export async function saveCacheManifest(manifest: CacheManifest): Promise<void> {
  const manifestPath = getManifestPath();
  await fs.mkdir(path.dirname(manifestPath), { recursive: true });
  await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
}

/**
 * Generate cache key from repo URL and commit
 */
export function generateCacheKey(repoUrl: string | undefined, commit: string): string {
  const repoHash = repoUrl
    ? Buffer.from(repoUrl).toString('base64url').slice(0, 16)
    : 'local';
  return `${repoHash}_${commit.slice(0, 12)}`;
}

/**
 * Get path for a cached artifact
 */
export function getCachePath(type: CacheEntry['type'], key: string): string {
  return path.join(getGlobalCacheRoot(), type, key);
}

/**
 * Check if a cached artifact exists
 */
export async function cacheExists(
  type: CacheEntry['type'],
  key: string
): Promise<boolean> {
  const cachePath = getCachePath(type, key);
  return existsSync(cachePath);
}

/**
 * Get a cached artifact entry
 */
export async function getCacheEntry(
  type: CacheEntry['type'],
  key: string
): Promise<CacheEntry | null> {
  const manifest = await loadCacheManifest();
  const entry = manifest.entries.find(e => e.type === type && e.key === key);

  if (entry) {
    // Update access time and count
    entry.last_accessed = new Date().toISOString();
    entry.access_count++;
    await saveCacheManifest(manifest);
  }

  return entry || null;
}

/**
 * Add a new cache entry
 */
export async function addCacheEntry(
  entry: Omit<CacheEntry, 'created_at' | 'last_accessed' | 'access_count'>
): Promise<void> {
  const manifest = await loadCacheManifest();

  // Check if entry already exists
  const existingIndex = manifest.entries.findIndex(
    e => e.type === entry.type && e.key === entry.key
  );

  const now = new Date().toISOString();
  const fullEntry: CacheEntry = {
    ...entry,
    created_at: now,
    last_accessed: now,
    access_count: 1,
  };

  if (existingIndex >= 0) {
    // Update existing entry
    manifest.entries[existingIndex] = fullEntry;
  } else {
    // Add new entry
    manifest.entries.push(fullEntry);
    manifest.total_size += entry.size;
  }

  await saveCacheManifest(manifest);

  // Trigger cleanup if cache is too large
  if (manifest.total_size > MAX_CACHE_SIZE_BYTES) {
    await cleanupCache();
  }
}

/**
 * Remove a cache entry
 */
export async function removeCacheEntry(
  type: CacheEntry['type'],
  key: string
): Promise<void> {
  const manifest = await loadCacheManifest();
  const entryIndex = manifest.entries.findIndex(
    e => e.type === type && e.key === key
  );

  if (entryIndex >= 0) {
    const entry = manifest.entries[entryIndex];
    manifest.total_size -= entry.size;
    manifest.entries.splice(entryIndex, 1);

    // Delete the actual files
    await fs.rm(entry.path, { recursive: true, force: true });

    await saveCacheManifest(manifest);
  }
}

/**
 * Clean up old cache entries to stay under size limit
 * Uses LRU eviction strategy
 */
export async function cleanupCache(
  maxSizeBytes: number = MAX_CACHE_SIZE_BYTES
): Promise<number> {
  const manifest = await loadCacheManifest();

  if (manifest.total_size <= maxSizeBytes) {
    return 0;
  }

  // Sort by last_accessed (oldest first)
  const sortedEntries = [...manifest.entries].sort(
    (a, b) => new Date(a.last_accessed).getTime() - new Date(b.last_accessed).getTime()
  );

  let bytesFreed = 0;
  const entriesToRemove: CacheEntry[] = [];

  for (const entry of sortedEntries) {
    if (manifest.total_size - bytesFreed <= maxSizeBytes) {
      break;
    }
    entriesToRemove.push(entry);
    bytesFreed += entry.size;
  }

  // Remove entries
  for (const entry of entriesToRemove) {
    await fs.rm(entry.path, { recursive: true, force: true });
    const index = manifest.entries.findIndex(
      e => e.type === entry.type && e.key === entry.key
    );
    if (index >= 0) {
      manifest.entries.splice(index, 1);
    }
  }

  manifest.total_size -= bytesFreed;
  manifest.last_cleanup = new Date().toISOString();
  await saveCacheManifest(manifest);

  return bytesFreed;
}

/**
 * Get cache statistics
 */
export async function getCacheStats(): Promise<{
  totalSize: number;
  entryCount: number;
  byType: Record<CacheEntry['type'], { count: number; size: number }>;
}> {
  const manifest = await loadCacheManifest();

  const byType: Record<CacheEntry['type'], { count: number; size: number }> = {
    'codeql-db': { count: 0, size: 0 },
    'joern-cpg': { count: 0, size: 0 },
    'symbol-index': { count: 0, size: 0 },
  };

  for (const entry of manifest.entries) {
    byType[entry.type].count++;
    byType[entry.type].size += entry.size;
  }

  return {
    totalSize: manifest.total_size,
    entryCount: manifest.entries.length,
    byType,
  };
}

/**
 * Clear all cached artifacts
 */
export async function clearCache(): Promise<void> {
  const cacheRoot = getGlobalCacheRoot();
  await fs.rm(cacheRoot, { recursive: true, force: true });
  await fs.mkdir(cacheRoot, { recursive: true });
  await saveCacheManifest({
    version: CACHE_MANIFEST_VERSION,
    entries: [],
    total_size: 0,
    last_cleanup: new Date().toISOString(),
  });
}

/**
 * Get directory size recursively
 */
export async function getDirectorySize(dirPath: string): Promise<number> {
  let totalSize = 0;

  async function walkDir(dir: string): Promise<void> {
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          await walkDir(fullPath);
        } else {
          const stat = await fs.stat(fullPath);
          totalSize += stat.size;
        }
      }
    } catch {
      // Ignore errors (permission denied, etc.)
    }
  }

  await walkDir(dirPath);
  return totalSize;
}

/**
 * Copy cached artifact to workspace
 */
export async function copyCacheToWorkspace(
  type: CacheEntry['type'],
  key: string,
  targetPath: string
): Promise<boolean> {
  const entry = await getCacheEntry(type, key);
  if (!entry || !existsSync(entry.path)) {
    return false;
  }

  await fs.cp(entry.path, targetPath, { recursive: true });
  return true;
}

/**
 * Save workspace artifact to cache
 */
export async function saveToCache(
  sourcePath: string,
  type: CacheEntry['type'],
  key: string,
  options: {
    commit: string;
    repo_url?: string;
    languages?: string[];
  }
): Promise<void> {
  const cachePath = getCachePath(type, key);

  // Ensure cache directory exists
  await fs.mkdir(path.dirname(cachePath), { recursive: true });

  // Copy to cache
  await fs.cp(sourcePath, cachePath, { recursive: true });

  // Get size
  const size = await getDirectorySize(cachePath);

  // Add entry
  await addCacheEntry({
    key,
    type,
    path: cachePath,
    size,
    commit: options.commit,
    repo_url: options.repo_url,
    languages: options.languages,
  });
}
