/**
 * Repository Tools
 *
 * Tools for repository operations: cloning, file listing, language detection.
 * These are used by RepoIntakeAgent and other agents that need repo access.
 */

import { tool } from 'ai';
import { z } from 'zod';
import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { existsSync } from 'fs';
import type { WorkspacePaths } from '../workspace';
import type { LanguageInfo, SecurityHotspot } from '../types';
import {
  EXCLUDE_DIRS,
  LANGUAGE_EXTENSIONS,
  SECURITY_PATTERNS,
  BUILD_SYSTEM_INDICATORS,
  LIMITS,
  getLanguageFromExtension,
} from '../constants';
import { walkDirectory, searchFiles, countFilesByLanguage } from '../utils/file-walker';

const execAsync = promisify(exec);

// Define schemas for type inference
const ListFilesSchema = z.object({
  directory: z.string().optional().describe('Subdirectory to list (relative to repo root)'),
  extensions: z.array(z.string()).optional().describe('Filter by file extensions (e.g., [".py", ".js"])'),
  maxFiles: z.number().optional().default(1000).describe('Maximum number of files to return'),
});

const ReadFileSchema = z.object({
  filePath: z.string().describe('Path to file relative to repo root'),
  startLine: z.number().optional().describe('Start line (1-indexed)'),
  endLine: z.number().optional().describe('End line (1-indexed)'),
});

const EmptyRepoSchema = z.object({});

const FindHotspotsSchema = z.object({
  maxFiles: z.number().optional().default(50).describe('Maximum number of hotspots to return'),
});

const SearchCodeSchema = z.object({
  pattern: z.string().describe('Regex pattern to search for'),
  fileExtensions: z.array(z.string()).optional().describe('File extensions to search (e.g., [".py", ".js"])'),
  maxResults: z.number().optional().default(100).describe('Maximum number of results'),
});

/**
 * Create repository tools for an agent
 */
export function createRepoTools(paths: WorkspacePaths) {
  const repoPath = paths.repo;

  /**
   * List all files in the repository
   */
  const list_files = tool({
    description: 'List all files in the repository, optionally filtered by extension or directory',
    inputSchema: ListFilesSchema,
    execute: async ({ directory, extensions, maxFiles }: z.infer<typeof ListFilesSchema>) => {
      const targetDir = directory ? path.join(repoPath, directory) : repoPath;

      const { files, truncated } = await walkDirectory(targetDir, {
        extensions,
        maxFiles,
      });

      return {
        success: true,
        files: files.map(f => path.relative(repoPath, f.fullPath)),
        count: files.length,
        truncated,
      };
    },
  });

  /**
   * Read file contents
   */
  const read_file = tool({
    description: 'Read the contents of a file in the repository',
    inputSchema: ReadFileSchema,
    execute: async ({ filePath, startLine, endLine }: z.infer<typeof ReadFileSchema>) => {
      const fullPath = path.join(repoPath, filePath);

      if (!existsSync(fullPath)) {
        return { success: false, error: `File not found: ${filePath}` };
      }

      try {
        const content = await fs.readFile(fullPath, 'utf-8');
        let lines = content.split('\n');

        if (startLine || endLine) {
          const start = (startLine || 1) - 1;
          const end = endLine || lines.length;
          lines = lines.slice(start, end);
        }

        return {
          success: true,
          content: lines.join('\n'),
          lineCount: lines.length,
          totalLines: content.split('\n').length,
        };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  /**
   * Detect languages in the repository
   */
  const detect_languages = tool({
    description: 'Detect programming languages used in the repository based on file extensions',
    inputSchema: EmptyRepoSchema,
    execute: async () => {
      const languageCounts = await countFilesByLanguage(repoPath);

      const totalFiles = Object.values(languageCounts).reduce((sum, count) => sum + count, 0);

      const languages: LanguageInfo[] = Object.entries(languageCounts)
        .map(([name, files]) => ({
          name,
          files,
          pct: totalFiles > 0 ? files / totalFiles : 0,
        }))
        .sort((a, b) => b.files - a.files);

      return {
        success: true,
        languages,
        totalFiles,
      };
    },
  });

  /**
   * Detect build systems
   */
  const detect_build_systems = tool({
    description: 'Detect build systems and package managers in the repository',
    inputSchema: EmptyRepoSchema,
    execute: async () => {
      const buildSystems: string[] = [];
      const dependencyFiles: string[] = [];

      try {
        const entries = await fs.readdir(repoPath);

        for (const entry of entries) {
          const indicator = BUILD_SYSTEM_INDICATORS[entry];
          if (indicator) {
            if (!buildSystems.includes(indicator.buildSystem)) {
              buildSystems.push(indicator.buildSystem);
            }
            if (indicator.isDependencyFile) {
              dependencyFiles.push(entry);
            }
          }
        }
      } catch {
        // Ignore errors
      }

      return {
        success: true,
        buildSystems,
        dependencyFiles,
      };
    },
  });

  /**
   * Find security hotspots
   */
  const find_security_hotspots = tool({
    description: 'Find files that likely contain security-sensitive code based on filename and content patterns',
    inputSchema: FindHotspotsSchema,
    execute: async ({ maxFiles }: z.infer<typeof FindHotspotsSchema>) => {
      const hotspots: SecurityHotspot[] = [];
      const codeExtensions = ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.cs', '.cpp', '.c'];

      async function scanDir(dir: string, depth: number = 0): Promise<void> {
        if (hotspots.length >= maxFiles || depth > 15) return;

        try {
          const entries = await fs.readdir(dir, { withFileTypes: true });

          for (const entry of entries) {
            if (hotspots.length >= maxFiles) break;

            const fullPath = path.join(dir, entry.name);
            const relativePath = path.relative(repoPath, fullPath);

            if (entry.isDirectory()) {
              if (!EXCLUDE_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
                await scanDir(fullPath, depth + 1);
              }
            } else if (entry.isFile()) {
              const ext = path.extname(entry.name).toLowerCase();
              if (!codeExtensions.includes(ext)) continue;

              // Check filename patterns
              for (const { pattern, reason } of SECURITY_PATTERNS) {
                if (pattern.test(entry.name) || pattern.test(relativePath)) {
                  hotspots.push({ path: relativePath, reason: `filename suggests ${reason}` });
                  break;
                }
              }

              // Quick content scan for small files
              try {
                const stat = await fs.stat(fullPath);
                if (stat.size < 100000) { // < 100KB
                  const content = await fs.readFile(fullPath, 'utf-8');
                  for (const { pattern, reason } of SECURITY_PATTERNS) {
                    if (pattern.test(content)) {
                      const existing = hotspots.find(h => h.path === relativePath);
                      if (!existing) {
                        hotspots.push({ path: relativePath, reason });
                      }
                      break;
                    }
                  }
                }
              } catch {
                // Ignore read errors
              }
            }
          }
        } catch {
          // Ignore errors
        }
      }

      await scanDir(repoPath);

      return {
        success: true,
        hotspots: hotspots.slice(0, maxFiles),
        count: hotspots.length,
      };
    },
  });

  /**
   * Get git information
   */
  const get_git_info = tool({
    description: 'Get git repository information (commit, branch, remote)',
    inputSchema: EmptyRepoSchema,
    execute: async () => {
      try {
        const [commitResult, branchResult, remoteResult] = await Promise.all([
          execAsync('git rev-parse HEAD', { cwd: repoPath }).catch(() => ({ stdout: '' })),
          execAsync('git rev-parse --abbrev-ref HEAD', { cwd: repoPath }).catch(() => ({ stdout: '' })),
          execAsync('git remote get-url origin', { cwd: repoPath }).catch(() => ({ stdout: '' })),
        ]);

        return {
          success: true,
          commit: commitResult.stdout.trim(),
          branch: branchResult.stdout.trim(),
          remote: remoteResult.stdout.trim(),
        };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  /**
   * Search for patterns in files
   */
  const search_code = tool({
    description: 'Search for a pattern in code files using grep-like functionality',
    inputSchema: SearchCodeSchema,
    execute: async ({ pattern, fileExtensions, maxResults }: z.infer<typeof SearchCodeSchema>) => {
      const regex = new RegExp(pattern, 'gi');

      const results = await searchFiles(repoPath, regex, {
        extensions: fileExtensions,
        maxResults,
      });

      return {
        success: true,
        results,
        count: results.length,
        truncated: results.length >= maxResults,
      };
    },
  });

  return {
    list_files,
    read_file,
    detect_languages,
    detect_build_systems,
    find_security_hotspots,
    get_git_info,
    search_code,
  };
}
