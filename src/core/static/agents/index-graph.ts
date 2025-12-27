/**
 * IndexGraphAgent
 *
 * Builds a code navigation index for the repository:
 * - Symbol index (functions, classes, methods)
 * - Import/dependency graph
 * - Security-relevant function registry
 *
 * Uses pattern matching rather than full AST parsing for speed and language agnosticism.
 */

import type { WorkspacePaths } from '../workspace';
import type { StaticAnalysisState, StaticAgentResult, RepoInventory, LanguageInfo } from '../types';
import { saveState, appendToResultsJsonl } from '../workspace';
import fs from 'fs/promises';
import path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import {
  EXCLUDE_DIRS,
  getLanguageFromExtension,
} from '../constants';
import { walkDirectory } from '../utils/file-walker';

const execAsync = promisify(exec);

export interface IndexGraphInput {
  paths: WorkspacePaths;
  state: StaticAnalysisState;
  abortSignal?: AbortSignal;
}

interface SymbolEntry {
  name: string;
  type: 'function' | 'class' | 'method' | 'variable' | 'import';
  file: string;
  line: number;
  language: string;
  signature?: string;
  securityRelevant?: boolean;
  securityReason?: string;
}

interface ImportEntry {
  file: string;
  imports: string[];
  language: string;
}

interface CodeIndex {
  symbols: SymbolEntry[];
  imports: ImportEntry[];
  securityFunctions: SymbolEntry[];
  stats: {
    totalSymbols: number;
    totalFiles: number;
    byLanguage: Record<string, number>;
    securityRelevantCount: number;
  };
}

// Security-relevant function patterns by category
const SECURITY_PATTERNS: Record<string, { pattern: RegExp; reason: string }[]> = {
  authentication: [
    { pattern: /\b(login|logout|authenticate|verify_password|check_auth|is_authenticated)\b/i, reason: 'authentication' },
    { pattern: /\b(jwt|token|session|cookie)\b/i, reason: 'session management' },
  ],
  authorization: [
    { pattern: /\b(authorize|is_admin|has_permission|check_role|can_access)\b/i, reason: 'authorization' },
    { pattern: /\b(rbac|acl|permission)\b/i, reason: 'access control' },
  ],
  cryptography: [
    { pattern: /\b(encrypt|decrypt|hash|hmac|sign|verify_signature)\b/i, reason: 'cryptography' },
    { pattern: /\b(aes|rsa|sha256|bcrypt|argon2)\b/i, reason: 'crypto algorithm' },
  ],
  injection: [
    { pattern: /\b(execute|query|raw_query|exec|eval|system|popen|subprocess)\b/i, reason: 'command/query execution' },
    { pattern: /\b(render|template|format_string)\b/i, reason: 'template rendering' },
  ],
  fileOps: [
    { pattern: /\b(read_file|write_file|open|upload|download|save_file)\b/i, reason: 'file operations' },
    { pattern: /\b(path_join|resolve_path|get_path)\b/i, reason: 'path handling' },
  ],
  network: [
    { pattern: /\b(request|fetch|http_get|http_post|curl|wget)\b/i, reason: 'network requests' },
    { pattern: /\b(redirect|forward|proxy)\b/i, reason: 'request routing' },
  ],
  serialization: [
    { pattern: /\b(serialize|deserialize|pickle|unmarshal|from_json|parse)\b/i, reason: 'serialization' },
    { pattern: /\b(yaml_load|xml_parse|json_decode)\b/i, reason: 'data parsing' },
  ],
};

// Language-specific patterns for symbol extraction
const LANGUAGE_PATTERNS: Record<string, {
  function: RegExp;
  class: RegExp;
  method: RegExp;
  import: RegExp;
}> = {
  python: {
    function: /^(?:async\s+)?def\s+(\w+)\s*\(/gm,
    class: /^class\s+(\w+)[\s:(]/gm,
    method: /^\s+(?:async\s+)?def\s+(\w+)\s*\(/gm,
    import: /^(?:from\s+[\w.]+\s+)?import\s+(.+)$/gm,
  },
  javascript: {
    function: /(?:^|\s)(?:async\s+)?function\s+(\w+)\s*\(/gm,
    class: /^class\s+(\w+)[\s{]/gm,
    method: /^\s+(?:async\s+)?(\w+)\s*\([^)]*\)\s*{/gm,
    import: /^import\s+(?:{[^}]+}|\w+|\*\s+as\s+\w+)\s+from\s+['"]([^'"]+)['"]/gm,
  },
  typescript: {
    function: /(?:^|\s)(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*[<(]/gm,
    class: /^(?:export\s+)?class\s+(\w+)[\s<{]/gm,
    method: /^\s+(?:public|private|protected|async|static|\s)*(\w+)\s*[<(][^)]*[)>]\s*[:{]/gm,
    import: /^import\s+(?:{[^}]+}|\w+|\*\s+as\s+\w+)\s+from\s+['"]([^'"]+)['"]/gm,
  },
  java: {
    function: /(?:public|private|protected|static|\s)+\w+(?:<[^>]+>)?\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+(?:,\s*\w+)*)?\s*{/gm,
    class: /(?:public|private|protected|\s)*class\s+(\w+)[\s<{]/gm,
    method: /(?:public|private|protected|static|\s)+\w+(?:<[^>]+>)?\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+(?:,\s*\w+)*)?\s*{/gm,
    import: /^import\s+([\w.]+);/gm,
  },
  go: {
    function: /^func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(/gm,
    class: /^type\s+(\w+)\s+struct\s*{/gm,
    method: /^func\s+\([^)]+\)\s+(\w+)\s*\(/gm,
    import: /^\s*"([^"]+)"/gm,
  },
  ruby: {
    function: /^def\s+(\w+)/gm,
    class: /^class\s+(\w+)/gm,
    method: /^\s+def\s+(\w+)/gm,
    import: /^require(?:_relative)?\s+['"]([^'"]+)['"]/gm,
  },
};

// Using shared EXCLUDE_DIRS and getLanguageFromExtension from constants

export async function runIndexGraphAgent(input: IndexGraphInput): Promise<StaticAgentResult> {
  const { paths, state, abortSignal } = input;
  const startTime = Date.now();
  const artifacts: string[] = [];

  try {
    const indexDir = paths.artifacts.index;
    const repoPath = paths.repo;
    const inventory = state.inventory;

    // Initialize index
    const index: CodeIndex = {
      symbols: [],
      imports: [],
      securityFunctions: [],
      stats: {
        totalSymbols: 0,
        totalFiles: 0,
        byLanguage: {},
        securityRelevantCount: 0,
      },
    };

    // Get primary languages
    const languages = inventory?.languages || [];
    const primaryLanguages = languages.filter(l => l.pct > 0.05).map(l => l.name);

    // Process files
    const files = await collectCodeFiles(repoPath, primaryLanguages);
    index.stats.totalFiles = files.length;

    for (const file of files) {
      if (abortSignal?.aborted) break;

      const relativePath = path.relative(repoPath, file.path);
      const lang = file.language;

      try {
        const content = await fs.readFile(file.path, 'utf-8');
        const fileSymbols = extractSymbols(content, relativePath, lang);
        const fileImports = extractImports(content, relativePath, lang);

        // Mark security-relevant symbols
        for (const symbol of fileSymbols) {
          const securityMatch = checkSecurityRelevance(symbol.name);
          if (securityMatch) {
            symbol.securityRelevant = true;
            symbol.securityReason = securityMatch;
            index.securityFunctions.push(symbol);
          }
        }

        index.symbols.push(...fileSymbols);
        if (fileImports.imports.length > 0) {
          index.imports.push(fileImports);
        }

        index.stats.byLanguage[lang] = (index.stats.byLanguage[lang] || 0) + fileSymbols.length;
      } catch {
        // Skip files that can't be read
      }
    }

    index.stats.totalSymbols = index.symbols.length;
    index.stats.securityRelevantCount = index.securityFunctions.length;

    // Save symbol index
    const symbolsPath = path.join(indexDir, 'symbols.json');
    await fs.writeFile(symbolsPath, JSON.stringify({
      generated: new Date().toISOString(),
      symbols: index.symbols,
      stats: index.stats,
    }, null, 2));
    artifacts.push(symbolsPath);

    // Save import graph
    const importsPath = path.join(indexDir, 'imports.json');
    await fs.writeFile(importsPath, JSON.stringify({
      generated: new Date().toISOString(),
      imports: index.imports,
    }, null, 2));
    artifacts.push(importsPath);

    // Save security-relevant functions index
    const securityPath = path.join(indexDir, 'security-functions.json');
    await fs.writeFile(securityPath, JSON.stringify({
      generated: new Date().toISOString(),
      functions: index.securityFunctions,
      count: index.securityFunctions.length,
      byCategory: groupBySecurityCategory(index.securityFunctions),
    }, null, 2));
    artifacts.push(securityPath);

    // Create hotspot ranking based on security function density
    const hotspotRanking = createHotspotRanking(index.securityFunctions, inventory?.security_hotspots || []);
    const hotspotPath = path.join(indexDir, 'hotspot-ranking.json');
    await fs.writeFile(hotspotPath, JSON.stringify({
      generated: new Date().toISOString(),
      ranking: hotspotRanking,
    }, null, 2));
    artifacts.push(hotspotPath);

    // Update state
    state.index = {
      symbol_index: symbolsPath,
      call_graph: path.join(indexDir, 'call_graph.json'), // Not implemented yet
      import_graph: importsPath,
      dep_graph: path.join(indexDir, 'deps.json'), // Not implemented yet
      hotspot_ranking: hotspotRanking.map(h => h.path),
    };

    await saveState(paths, state);

    await appendToResultsJsonl(paths, {
      type: 'agent_complete',
      agent: 'index-graph',
      success: true,
      duration_ms: Date.now() - startTime,
      stats: index.stats,
    });

    return {
      stage: 'index-graph',
      success: true,
      artifacts,
      summary: `Indexed ${index.stats.totalSymbols} symbols from ${index.stats.totalFiles} files, ${index.stats.securityRelevantCount} security-relevant functions`,
      duration_ms: Date.now() - startTime,
    };
  } catch (error: any) {
    return {
      stage: 'index-graph',
      success: false,
      artifacts: [],
      summary: `Index stage failed: ${error.message}`,
      error: error.message,
      duration_ms: Date.now() - startTime,
    };
  }
}

/**
 * Collect all code files from the repository
 */
async function collectCodeFiles(
  repoPath: string,
  primaryLanguages: string[]
): Promise<Array<{ path: string; language: string }>> {
  const { files } = await walkDirectory(repoPath, {
    maxDepth: 15,
    maxFiles: 5000,
    fileFilter: (fileName) => {
      const ext = path.extname(fileName).toLowerCase();
      const lang = getLanguageFromExtension(ext);
      return lang !== null && (primaryLanguages.length === 0 || primaryLanguages.includes(lang));
    },
  });

  return files.map(f => ({
    path: f.fullPath,
    language: getLanguageFromExtension(path.extname(f.path).toLowerCase())!,
  }));
}

// Using getLanguageFromExtension from shared constants

/**
 * Extract symbols from file content
 */
function extractSymbols(content: string, filePath: string, language: string): SymbolEntry[] {
  const symbols: SymbolEntry[] = [];
  const patterns = LANGUAGE_PATTERNS[language];
  if (!patterns) return symbols;

  const lines = content.split('\n');

  // Extract functions
  let match;
  const funcPattern = new RegExp(patterns.function.source, 'gm');
  while ((match = funcPattern.exec(content)) !== null) {
    const line = content.slice(0, match.index).split('\n').length;
    symbols.push({
      name: match[1],
      type: 'function',
      file: filePath,
      line,
      language,
      signature: lines[line - 1]?.trim().slice(0, 100),
    });
  }

  // Extract classes
  const classPattern = new RegExp(patterns.class.source, 'gm');
  while ((match = classPattern.exec(content)) !== null) {
    const line = content.slice(0, match.index).split('\n').length;
    symbols.push({
      name: match[1],
      type: 'class',
      file: filePath,
      line,
      language,
    });
  }

  return symbols;
}

/**
 * Extract imports from file content
 */
function extractImports(content: string, filePath: string, language: string): ImportEntry {
  const imports: string[] = [];
  const patterns = LANGUAGE_PATTERNS[language];
  if (!patterns) return { file: filePath, imports: [], language };

  let match;
  const importPattern = new RegExp(patterns.import.source, 'gm');
  while ((match = importPattern.exec(content)) !== null) {
    imports.push(match[1]);
  }

  return { file: filePath, imports, language };
}

/**
 * Check if a symbol name is security-relevant
 */
function checkSecurityRelevance(name: string): string | null {
  for (const [category, patterns] of Object.entries(SECURITY_PATTERNS)) {
    for (const { pattern, reason } of patterns) {
      if (pattern.test(name)) {
        return reason;
      }
    }
  }
  return null;
}

/**
 * Group security functions by category
 */
function groupBySecurityCategory(functions: SymbolEntry[]): Record<string, string[]> {
  const grouped: Record<string, string[]> = {};

  for (const func of functions) {
    const reason = func.securityReason || 'other';
    if (!grouped[reason]) grouped[reason] = [];
    grouped[reason].push(`${func.file}:${func.line} ${func.name}`);
  }

  return grouped;
}

/**
 * Create hotspot ranking combining security functions and previous hotspots
 */
function createHotspotRanking(
  securityFunctions: SymbolEntry[],
  existingHotspots: Array<{ path: string; reason: string }>
): Array<{ path: string; score: number; reasons: string[] }> {
  const fileScores = new Map<string, { score: number; reasons: Set<string> }>();

  // Score from security functions
  for (const func of securityFunctions) {
    const existing = fileScores.get(func.file) || { score: 0, reasons: new Set() };
    existing.score += 2;
    if (func.securityReason) existing.reasons.add(func.securityReason);
    fileScores.set(func.file, existing);
  }

  // Score from existing hotspots
  for (const hotspot of existingHotspots) {
    const existing = fileScores.get(hotspot.path) || { score: 0, reasons: new Set() };
    existing.score += 1;
    existing.reasons.add(hotspot.reason);
    fileScores.set(hotspot.path, existing);
  }

  // Convert to sorted array
  return Array.from(fileScores.entries())
    .map(([path, { score, reasons }]) => ({ path, score, reasons: Array.from(reasons) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 50);
}
