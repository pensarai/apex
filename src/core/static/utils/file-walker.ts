/**
 * File Walker Utility
 *
 * Shared recursive directory walking implementation.
 * Eliminates DRY violations across index-graph, repo-tools, and cache.
 */

import fs from 'fs/promises';
import { Stats } from 'fs';
import path from 'path';
import { EXCLUDE_DIRS, LIMITS } from '../constants';

export interface WalkOptions {
  /** Maximum directory depth (default: LIMITS.MAX_DEPTH) */
  maxDepth?: number;

  /** Maximum files to collect (default: LIMITS.MAX_FILES) */
  maxFiles?: number;

  /** File extensions to include (if specified, only matching files are included) */
  extensions?: string[];

  /** Custom directory filter (return false to skip directory) */
  dirFilter?: (dirName: string, fullPath: string) => boolean;

  /** Custom file filter (return false to skip file) */
  fileFilter?: (fileName: string, fullPath: string, stats?: Stats) => boolean;

  /** Include file stats in results */
  includeStats?: boolean;

  /** Abort signal for cancellation */
  abortSignal?: AbortSignal;
}

export interface WalkResult {
  /** Relative path from root */
  path: string;

  /** Full absolute path */
  fullPath: string;

  /** Whether this is a file or directory */
  isFile: boolean;

  /** File stats (if includeStats: true) */
  stats?: Stats;
}

export interface WalkSummary {
  /** Files found */
  files: WalkResult[];

  /** Total files processed */
  totalProcessed: number;

  /** Whether results were truncated due to limits */
  truncated: boolean;

  /** Directories skipped */
  directoriesSkipped: number;
}

/**
 * Walk a directory tree recursively with configurable filtering
 *
 * @param rootPath - Root directory to start walking
 * @param options - Walk configuration options
 * @returns Summary of walk results
 *
 * @example
 * // Walk all Python files
 * const { files } = await walkDirectory('/repo', { extensions: ['.py'] });
 *
 * @example
 * // Walk with custom filter
 * const { files } = await walkDirectory('/repo', {
 *   fileFilter: (name) => name.includes('test'),
 * });
 */
export async function walkDirectory(
  rootPath: string,
  options: WalkOptions = {}
): Promise<WalkSummary> {
  const {
    maxDepth = LIMITS.MAX_DEPTH,
    maxFiles = LIMITS.MAX_FILES,
    extensions,
    dirFilter,
    fileFilter,
    includeStats = false,
    abortSignal,
  } = options;

  const files: WalkResult[] = [];
  let totalProcessed = 0;
  let directoriesSkipped = 0;

  async function walk(dir: string, depth: number): Promise<void> {
    // Check abort signal
    if (abortSignal?.aborted) return;

    // Check limits
    if (files.length >= maxFiles || depth > maxDepth) return;

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        // Check abort signal and limits on each iteration
        if (abortSignal?.aborted || files.length >= maxFiles) break;

        const fullPath = path.join(dir, entry.name);
        const relativePath = path.relative(rootPath, fullPath);

        if (entry.isDirectory()) {
          // Check if directory should be excluded
          const shouldExclude =
            EXCLUDE_DIRS.has(entry.name) ||
            entry.name.startsWith('.') ||
            (dirFilter && !dirFilter(entry.name, fullPath));

          if (shouldExclude) {
            directoriesSkipped++;
            continue;
          }

          await walk(fullPath, depth + 1);
        } else if (entry.isFile()) {
          totalProcessed++;

          // Check extension filter
          if (extensions) {
            const ext = path.extname(entry.name).toLowerCase();
            if (!extensions.includes(ext)) continue;
          }

          // Check custom file filter
          if (fileFilter) {
            let stats: Stats | undefined;
            if (includeStats) {
              try {
                stats = await fs.stat(fullPath);
              } catch {
                continue; // Skip files we can't stat
              }
            }
            if (!fileFilter(entry.name, fullPath, stats)) continue;
          }

          // Get stats if requested
          let stats: Stats | undefined;
          if (includeStats) {
            try {
              stats = await fs.stat(fullPath);
            } catch {
              // Skip if we can't get stats
            }
          }

          files.push({
            path: relativePath,
            fullPath,
            isFile: true,
            stats,
          });
        }
      }
    } catch {
      // Ignore permission errors and other read failures
    }
  }

  await walk(rootPath, 0);

  return {
    files,
    totalProcessed,
    truncated: files.length >= maxFiles,
    directoriesSkipped,
  };
}

/**
 * Collect files matching criteria (simplified interface for common use case)
 */
export async function collectFiles(
  rootPath: string,
  options: {
    extensions?: string[];
    maxFiles?: number;
    abortSignal?: AbortSignal;
  } = {}
): Promise<{ path: string; language: string | null }[]> {
  const { files } = await walkDirectory(rootPath, {
    extensions: options.extensions,
    maxFiles: options.maxFiles,
    abortSignal: options.abortSignal,
  });

  // Import dynamically to avoid circular dependency
  const { getLanguageFromExtension } = await import('../constants');

  return files.map(f => ({
    path: f.fullPath,
    language: getLanguageFromExtension(path.extname(f.path)),
  }));
}

/**
 * Search for files containing a pattern
 */
export async function searchFiles(
  rootPath: string,
  pattern: RegExp,
  options: {
    extensions?: string[];
    maxResults?: number;
    maxFileSize?: number;
    abortSignal?: AbortSignal;
  } = {}
): Promise<Array<{ file: string; line: number; content: string }>> {
  const {
    extensions,
    maxResults = LIMITS.MAX_SEARCH_RESULTS,
    maxFileSize = LIMITS.MAX_SEARCHABLE_SIZE,
    abortSignal,
  } = options;

  const results: Array<{ file: string; line: number; content: string }> = [];

  const { files } = await walkDirectory(rootPath, {
    extensions,
    maxFiles: LIMITS.MAX_FILES,
    includeStats: true,
    fileFilter: (_name, _path, stats) => {
      return !stats || stats.size <= maxFileSize;
    },
    abortSignal,
  });

  for (const file of files) {
    if (abortSignal?.aborted || results.length >= maxResults) break;

    try {
      const content = await fs.readFile(file.fullPath, 'utf-8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length && results.length < maxResults; i++) {
        if (pattern.test(lines[i]!)) {
          results.push({
            file: file.path,
            line: i + 1,
            content: lines[i]!.trim().substring(0, LIMITS.MAX_LINE_LENGTH),
          });
        }
      }
    } catch {
      // Skip unreadable files
    }
  }

  return results;
}

/**
 * Count files by language
 */
export async function countFilesByLanguage(
  rootPath: string,
  abortSignal?: AbortSignal
): Promise<Record<string, number>> {
  const { getLanguageFromExtension } = await import('../constants');
  const counts: Record<string, number> = {};

  const { files } = await walkDirectory(rootPath, { abortSignal });

  for (const file of files) {
    const ext = path.extname(file.path).toLowerCase();
    const lang = getLanguageFromExtension(ext);
    if (lang) {
      counts[lang] = (counts[lang] || 0) + 1;
    }
  }

  return counts;
}

/**
 * Get total directory size in bytes
 */
export async function getDirectorySize(dirPath: string): Promise<number> {
  let totalSize = 0;

  const { files } = await walkDirectory(dirPath, { includeStats: true });

  for (const file of files) {
    if (file.stats) {
      totalSize += file.stats.size;
    }
  }

  return totalSize;
}
