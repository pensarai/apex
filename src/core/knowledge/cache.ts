/**
 * Disk-based Knowledge Cache
 *
 * Caches externally-fetched knowledge (from Nuclei API) to disk
 * with configurable TTL to minimize API calls during engagements.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, statSync, unlinkSync } from 'fs';
import { join } from 'path';

export interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number;
  source: string;
}

export interface CacheConfig {
  /** Directory to store cache files */
  cacheDir: string;
  /** Default TTL in milliseconds (default: 24 hours) */
  defaultTTL: number;
  /** Maximum cache size in MB (default: 100MB) */
  maxSizeMB: number;
}

const DEFAULT_CONFIG: CacheConfig = {
  cacheDir: '.apex-cache/knowledge',
  defaultTTL: 24 * 60 * 60 * 1000, // 24 hours
  maxSizeMB: 100,
};

/**
 * Knowledge Cache Manager
 *
 * Provides disk-based caching with TTL for external knowledge sources.
 */
export class KnowledgeCache {
  private config: CacheConfig;
  private memoryCache: Map<string, CacheEntry<any>> = new Map();

  constructor(config: Partial<CacheConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.ensureCacheDir();
  }

  private ensureCacheDir(): void {
    if (!existsSync(this.config.cacheDir)) {
      mkdirSync(this.config.cacheDir, { recursive: true });
    }
  }

  private getCacheFilePath(key: string): string {
    // Sanitize key for filesystem
    const safeKey = key.replace(/[^a-zA-Z0-9_-]/g, '_');
    return join(this.config.cacheDir, `${safeKey}.json`);
  }

  /**
   * Get cached data if not expired
   */
  get<T>(key: string): T | null {
    // Check memory cache first
    const memEntry = this.memoryCache.get(key);
    if (memEntry && !this.isExpired(memEntry)) {
      return memEntry.data as T;
    }

    // Check disk cache
    const filePath = this.getCacheFilePath(key);
    if (!existsSync(filePath)) {
      return null;
    }

    try {
      const content = readFileSync(filePath, 'utf-8');
      const entry: CacheEntry<T> = JSON.parse(content);

      if (this.isExpired(entry)) {
        // Remove expired entry
        this.delete(key);
        return null;
      }

      // Populate memory cache
      this.memoryCache.set(key, entry);
      return entry.data;
    } catch (error) {
      // Invalid cache file, remove it
      this.delete(key);
      return null;
    }
  }

  /**
   * Store data in cache with optional custom TTL
   */
  set<T>(key: string, data: T, options: { ttl?: number; source?: string } = {}): void {
    const entry: CacheEntry<T> = {
      data,
      timestamp: Date.now(),
      ttl: options.ttl ?? this.config.defaultTTL,
      source: options.source ?? 'unknown',
    };

    // Store in memory
    this.memoryCache.set(key, entry);

    // Store on disk
    const filePath = this.getCacheFilePath(key);
    try {
      writeFileSync(filePath, JSON.stringify(entry, null, 2));
    } catch (error) {
      console.error(`Failed to write cache file: ${filePath}`, error);
    }

    // Check cache size and cleanup if needed
    this.cleanupIfNeeded();
  }

  /**
   * Delete cached entry
   */
  delete(key: string): void {
    this.memoryCache.delete(key);
    const filePath = this.getCacheFilePath(key);
    if (existsSync(filePath)) {
      try {
        unlinkSync(filePath);
      } catch (error) {
        // Ignore deletion errors
      }
    }
  }

  /**
   * Check if entry has expired
   */
  private isExpired(entry: CacheEntry<any>): boolean {
    return Date.now() > entry.timestamp + entry.ttl;
  }

  /**
   * Get cache entry metadata without data
   */
  getMetadata(key: string): { timestamp: number; ttl: number; source: string; isExpired: boolean } | null {
    const filePath = this.getCacheFilePath(key);
    if (!existsSync(filePath)) {
      return null;
    }

    try {
      const content = readFileSync(filePath, 'utf-8');
      const entry: CacheEntry<any> = JSON.parse(content);
      return {
        timestamp: entry.timestamp,
        ttl: entry.ttl,
        source: entry.source,
        isExpired: this.isExpired(entry),
      };
    } catch {
      return null;
    }
  }

  /**
   * Force refresh - delete and re-fetch will happen on next get
   */
  invalidate(key: string): void {
    this.delete(key);
  }

  /**
   * Invalidate all entries matching a pattern
   */
  invalidatePattern(pattern: string | RegExp): number {
    const regex = typeof pattern === 'string' ? new RegExp(pattern) : pattern;
    let count = 0;

    // Clear from memory
    for (const key of this.memoryCache.keys()) {
      if (regex.test(key)) {
        this.memoryCache.delete(key);
        count++;
      }
    }

    // Clear from disk
    if (existsSync(this.config.cacheDir)) {
      const files = readdirSync(this.config.cacheDir);
      for (const file of files) {
        if (file.endsWith('.json') && regex.test(file.replace('.json', ''))) {
          try {
            unlinkSync(join(this.config.cacheDir, file));
            count++;
          } catch {
            // Ignore errors
          }
        }
      }
    }

    return count;
  }

  /**
   * Clear all cached data
   */
  clear(): void {
    this.memoryCache.clear();

    if (existsSync(this.config.cacheDir)) {
      const files = readdirSync(this.config.cacheDir);
      for (const file of files) {
        if (file.endsWith('.json')) {
          try {
            unlinkSync(join(this.config.cacheDir, file));
          } catch {
            // Ignore errors
          }
        }
      }
    }
  }

  /**
   * Get current cache size in bytes
   */
  getCacheSize(): number {
    if (!existsSync(this.config.cacheDir)) {
      return 0;
    }

    let totalSize = 0;
    const files = readdirSync(this.config.cacheDir);
    for (const file of files) {
      if (file.endsWith('.json')) {
        try {
          const stats = statSync(join(this.config.cacheDir, file));
          totalSize += stats.size;
        } catch {
          // Ignore errors
        }
      }
    }
    return totalSize;
  }

  /**
   * Cleanup expired entries and enforce size limit
   */
  private cleanupIfNeeded(): void {
    const maxBytes = this.config.maxSizeMB * 1024 * 1024;
    const currentSize = this.getCacheSize();

    if (currentSize < maxBytes) {
      return;
    }

    // Remove expired entries first
    this.cleanupExpired();

    // If still over limit, remove oldest entries
    if (this.getCacheSize() >= maxBytes) {
      this.cleanupOldest(maxBytes * 0.8); // Target 80% of max
    }
  }

  /**
   * Remove all expired entries
   */
  cleanupExpired(): number {
    let count = 0;

    if (!existsSync(this.config.cacheDir)) {
      return 0;
    }

    const files = readdirSync(this.config.cacheDir);
    for (const file of files) {
      if (file.endsWith('.json')) {
        const filePath = join(this.config.cacheDir, file);
        try {
          const content = readFileSync(filePath, 'utf-8');
          const entry: CacheEntry<any> = JSON.parse(content);
          if (this.isExpired(entry)) {
            unlinkSync(filePath);
            this.memoryCache.delete(file.replace('.json', ''));
            count++;
          }
        } catch {
          // Invalid file, remove it
          try {
            unlinkSync(filePath);
            count++;
          } catch {
            // Ignore
          }
        }
      }
    }

    return count;
  }

  /**
   * Remove oldest entries until under target size
   */
  private cleanupOldest(targetBytes: number): void {
    if (!existsSync(this.config.cacheDir)) {
      return;
    }

    // Get all entries with timestamps
    const entries: Array<{ file: string; timestamp: number; size: number }> = [];
    const files = readdirSync(this.config.cacheDir);

    for (const file of files) {
      if (file.endsWith('.json')) {
        const filePath = join(this.config.cacheDir, file);
        try {
          const content = readFileSync(filePath, 'utf-8');
          const entry: CacheEntry<any> = JSON.parse(content);
          const stats = statSync(filePath);
          entries.push({ file, timestamp: entry.timestamp, size: stats.size });
        } catch {
          // Skip invalid files
        }
      }
    }

    // Sort by timestamp (oldest first)
    entries.sort((a, b) => a.timestamp - b.timestamp);

    // Remove oldest until under target
    let currentSize = entries.reduce((sum, e) => sum + e.size, 0);
    for (const entry of entries) {
      if (currentSize <= targetBytes) {
        break;
      }
      try {
        unlinkSync(join(this.config.cacheDir, entry.file));
        this.memoryCache.delete(entry.file.replace('.json', ''));
        currentSize -= entry.size;
      } catch {
        // Ignore errors
      }
    }
  }

  /**
   * List all cached keys
   */
  listKeys(): string[] {
    if (!existsSync(this.config.cacheDir)) {
      return [];
    }

    const files = readdirSync(this.config.cacheDir);
    return files
      .filter(f => f.endsWith('.json'))
      .map(f => f.replace('.json', ''));
  }

  /**
   * Get cache statistics
   */
  getStats(): {
    totalEntries: number;
    totalSizeBytes: number;
    expiredEntries: number;
    oldestEntry: Date | null;
    newestEntry: Date | null;
  } {
    const keys = this.listKeys();
    let totalSize = 0;
    let expiredCount = 0;
    let oldest: number | null = null;
    let newest: number | null = null;

    for (const key of keys) {
      const meta = this.getMetadata(key);
      if (meta) {
        if (meta.isExpired) expiredCount++;
        if (oldest === null || meta.timestamp < oldest) oldest = meta.timestamp;
        if (newest === null || meta.timestamp > newest) newest = meta.timestamp;
      }
    }

    totalSize = this.getCacheSize();

    return {
      totalEntries: keys.length,
      totalSizeBytes: totalSize,
      expiredEntries: expiredCount,
      oldestEntry: oldest ? new Date(oldest) : null,
      newestEntry: newest ? new Date(newest) : null,
    };
  }
}

// Singleton instance for global use
let globalCache: KnowledgeCache | null = null;

/**
 * Get the global knowledge cache instance
 */
export function getKnowledgeCache(config?: Partial<CacheConfig>): KnowledgeCache {
  if (!globalCache) {
    globalCache = new KnowledgeCache(config);
  }
  return globalCache;
}

/**
 * Reset the global cache (mainly for testing)
 */
export function resetKnowledgeCache(): void {
  if (globalCache) {
    globalCache.clear();
    globalCache = null;
  }
}

// Cache key generators for consistent naming
export const CacheKeys = {
  techKnowledge: (tech: string) => `tech_${tech.toLowerCase()}`,
  cveTemplates: (query: string) => `cve_${query.toLowerCase().replace(/[^a-z0-9]/g, '_')}`,
  techDiscovery: () => 'tech_discovery',
  wordlist: (tech: string, type: string) => `wordlist_${tech}_${type}`,
};
