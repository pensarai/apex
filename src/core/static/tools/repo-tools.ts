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
 * Language detection based on file extensions
 */
const LANGUAGE_EXTENSIONS: Record<string, string[]> = {
  python: ['.py', '.pyw', '.pyi'],
  javascript: ['.js', '.mjs', '.cjs'],
  typescript: ['.ts', '.tsx', '.mts', '.cts'],
  java: ['.java'],
  kotlin: ['.kt', '.kts'],
  go: ['.go'],
  rust: ['.rs'],
  ruby: ['.rb', '.rake', '.gemspec'],
  php: ['.php', '.phtml'],
  csharp: ['.cs'],
  cpp: ['.cpp', '.cc', '.cxx', '.hpp', '.h', '.hxx'],
  c: ['.c'],
  swift: ['.swift'],
  scala: ['.scala', '.sc'],
  shell: ['.sh', '.bash', '.zsh'],
  sql: ['.sql'],
  html: ['.html', '.htm'],
  css: ['.css', '.scss', '.sass', '.less'],
  yaml: ['.yaml', '.yml'],
  json: ['.json'],
  xml: ['.xml'],
  markdown: ['.md', '.markdown'],
};

/**
 * Security-sensitive patterns to look for
 */
const SECURITY_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /auth|login|session|jwt|token|cookie/i, reason: 'authentication/session handling' },
  { pattern: /password|credential|secret|key/i, reason: 'credential handling' },
  { pattern: /pickle|marshal|yaml\.load|deserialize|unserialize/i, reason: 'deserialization' },
  { pattern: /exec|eval|system|popen|spawn|shell/i, reason: 'command execution' },
  { pattern: /sql|query|execute|cursor/i, reason: 'database operations' },
  { pattern: /upload|file|path|directory/i, reason: 'file operations' },
  { pattern: /http|request|fetch|curl|axios/i, reason: 'HTTP requests' },
  { pattern: /crypto|encrypt|decrypt|hash|aes|rsa/i, reason: 'cryptography' },
  { pattern: /render|template|jinja|mustache/i, reason: 'templating' },
  { pattern: /xml|parse|dom|sax/i, reason: 'XML parsing' },
];

/**
 * Directories to exclude from scanning
 */
const EXCLUDE_DIRS = new Set([
  'node_modules',
  'vendor',
  'venv',
  '.venv',
  '__pycache__',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  'target',
  'out',
  '.idea',
  '.vscode',
  'coverage',
  '.nyc_output',
  'tmp',
  'temp',
  'logs',
]);

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
      const files: string[] = [];

      async function walkDir(dir: string, depth: number = 0): Promise<void> {
        if (files.length >= maxFiles || depth > 20) return;

        try {
          const entries = await fs.readdir(dir, { withFileTypes: true });

          for (const entry of entries) {
            if (files.length >= maxFiles) break;

            const fullPath = path.join(dir, entry.name);
            const relativePath = path.relative(repoPath, fullPath);

            if (entry.isDirectory()) {
              if (!EXCLUDE_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
                await walkDir(fullPath, depth + 1);
              }
            } else if (entry.isFile()) {
              if (!extensions || extensions.some(ext => entry.name.endsWith(ext))) {
                files.push(relativePath);
              }
            }
          }
        } catch {
          // Ignore permission errors
        }
      }

      await walkDir(targetDir);

      return {
        success: true,
        files,
        count: files.length,
        truncated: files.length >= maxFiles,
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
      const languageCounts: Record<string, number> = {};
      let totalFiles = 0;

      async function countFiles(dir: string, depth: number = 0): Promise<void> {
        if (depth > 20) return;

        try {
          const entries = await fs.readdir(dir, { withFileTypes: true });

          for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);

            if (entry.isDirectory()) {
              if (!EXCLUDE_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
                await countFiles(fullPath, depth + 1);
              }
            } else if (entry.isFile()) {
              const ext = path.extname(entry.name).toLowerCase();

              for (const [lang, exts] of Object.entries(LANGUAGE_EXTENSIONS)) {
                if (exts.includes(ext)) {
                  languageCounts[lang] = (languageCounts[lang] || 0) + 1;
                  totalFiles++;
                  break;
                }
              }
            }
          }
        } catch {
          // Ignore errors
        }
      }

      await countFiles(repoPath);

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

      const indicators: Record<string, { buildSystem: string; isDependency: boolean }> = {
        'package.json': { buildSystem: 'npm/yarn', isDependency: true },
        'package-lock.json': { buildSystem: 'npm', isDependency: false },
        'yarn.lock': { buildSystem: 'yarn', isDependency: false },
        'pnpm-lock.yaml': { buildSystem: 'pnpm', isDependency: false },
        'requirements.txt': { buildSystem: 'pip', isDependency: true },
        'setup.py': { buildSystem: 'setuptools', isDependency: true },
        'pyproject.toml': { buildSystem: 'poetry/pip', isDependency: true },
        'Pipfile': { buildSystem: 'pipenv', isDependency: true },
        'go.mod': { buildSystem: 'go modules', isDependency: true },
        'Cargo.toml': { buildSystem: 'cargo', isDependency: true },
        'pom.xml': { buildSystem: 'maven', isDependency: true },
        'build.gradle': { buildSystem: 'gradle', isDependency: true },
        'build.gradle.kts': { buildSystem: 'gradle', isDependency: true },
        'Gemfile': { buildSystem: 'bundler', isDependency: true },
        'composer.json': { buildSystem: 'composer', isDependency: true },
        'CMakeLists.txt': { buildSystem: 'cmake', isDependency: false },
        'Makefile': { buildSystem: 'make', isDependency: false },
        'Dockerfile': { buildSystem: 'docker', isDependency: false },
        'docker-compose.yml': { buildSystem: 'docker-compose', isDependency: false },
      };

      try {
        const entries = await fs.readdir(repoPath);

        for (const entry of entries) {
          const indicator = indicators[entry];
          if (indicator) {
            if (!buildSystems.includes(indicator.buildSystem)) {
              buildSystems.push(indicator.buildSystem);
            }
            if (indicator.isDependency) {
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
      const results: Array<{ file: string; line: number; content: string }> = [];
      const regex = new RegExp(pattern, 'gi');

      async function searchDir(dir: string, depth: number = 0): Promise<void> {
        if (results.length >= maxResults || depth > 15) return;

        try {
          const entries = await fs.readdir(dir, { withFileTypes: true });

          for (const entry of entries) {
            if (results.length >= maxResults) break;

            const fullPath = path.join(dir, entry.name);
            const relativePath = path.relative(repoPath, fullPath);

            if (entry.isDirectory()) {
              if (!EXCLUDE_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
                await searchDir(fullPath, depth + 1);
              }
            } else if (entry.isFile()) {
              const ext = path.extname(entry.name).toLowerCase();
              if (fileExtensions && !fileExtensions.includes(ext)) continue;

              try {
                const stat = await fs.stat(fullPath);
                if (stat.size > 1000000) continue; // Skip files > 1MB

                const content = await fs.readFile(fullPath, 'utf-8');
                const lines = content.split('\n');

                for (let i = 0; i < lines.length && results.length < maxResults; i++) {
                  if (regex.test(lines[i]!)) {
                    results.push({
                      file: relativePath,
                      line: i + 1,
                      content: lines[i]!.trim().substring(0, 200),
                    });
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

      await searchDir(repoPath);

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
