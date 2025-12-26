/**
 * CodeQL Integration
 *
 * Wrapper for running CodeQL static analysis.
 * CodeQL provides deep semantic analysis with dataflow tracking.
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { existsSync } from 'fs';
import type { AnalysisRun, FindingSeverity } from '../types';

const execAsync = promisify(exec);

/**
 * CodeQL configuration
 */
export interface CodeQLConfig {
  /** Languages to analyze */
  languages: string[];
  /** Query packs to run */
  queryPacks?: string[];
  /** Custom queries directory */
  customQueries?: string;
  /** Threads for database creation */
  threads?: number;
  /** RAM for database creation (MB) */
  ram?: number;
  /** Timeout for queries (seconds) */
  timeout?: number;
}

/**
 * CodeQL SARIF result
 */
export interface CodeQLResult {
  ruleId: string;
  level: string;
  message: string;
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: {
        startLine: number;
        startColumn?: number;
        endLine?: number;
        endColumn?: number;
      };
    };
  }>;
  codeFlows?: Array<{
    threadFlows: Array<{
      locations: Array<{
        location: {
          physicalLocation: {
            artifactLocation: { uri: string };
            region: { startLine: number };
          };
          message?: { text: string };
        };
      }>;
    }>;
  }>;
  properties?: {
    'security-severity'?: string;
    tags?: string[];
    cwe?: string[];
  };
}

/**
 * Supported CodeQL languages and their build requirements
 */
export const CODEQL_LANGUAGES: Record<
  string,
  { supported: boolean; needsBuild: boolean; extractor: string }
> = {
  javascript: { supported: true, needsBuild: false, extractor: 'javascript' },
  typescript: { supported: true, needsBuild: false, extractor: 'javascript' },
  python: { supported: true, needsBuild: false, extractor: 'python' },
  java: { supported: true, needsBuild: true, extractor: 'java' },
  csharp: { supported: true, needsBuild: true, extractor: 'csharp' },
  cpp: { supported: true, needsBuild: true, extractor: 'cpp' },
  c: { supported: true, needsBuild: true, extractor: 'cpp' },
  go: { supported: true, needsBuild: true, extractor: 'go' },
  ruby: { supported: true, needsBuild: false, extractor: 'ruby' },
};

/**
 * Default query packs for security analysis
 */
const DEFAULT_QUERY_PACKS: Record<string, string[]> = {
  javascript: ['codeql/javascript-queries:codeql-suites/javascript-security-extended.qls'],
  python: ['codeql/python-queries:codeql-suites/python-security-extended.qls'],
  java: ['codeql/java-queries:codeql-suites/java-security-extended.qls'],
  csharp: ['codeql/csharp-queries:codeql-suites/csharp-security-extended.qls'],
  cpp: ['codeql/cpp-queries:codeql-suites/cpp-security-extended.qls'],
  go: ['codeql/go-queries:codeql-suites/go-security-extended.qls'],
  ruby: ['codeql/ruby-queries:codeql-suites/ruby-security-extended.qls'],
};

/**
 * Check if CodeQL is available
 */
export async function isCodeQLAvailable(): Promise<boolean> {
  try {
    await execAsync('codeql version');
    return true;
  } catch {
    return false;
  }
}

/**
 * Create a CodeQL database for a repository
 */
export async function createCodeQLDatabase(
  repoPath: string,
  language: string,
  outputDir: string,
  config: Partial<CodeQLConfig> = {}
): Promise<{ dbPath: string; success: boolean; error?: string }> {
  const langInfo = CODEQL_LANGUAGES[language.toLowerCase()];
  if (!langInfo?.supported) {
    return {
      dbPath: '',
      success: false,
      error: `Language '${language}' is not supported by CodeQL`,
    };
  }

  const dbPath = path.join(outputDir, `codeql-db-${langInfo.extractor}`);

  // Build the database creation command
  const args = [
    'codeql',
    'database',
    'create',
    dbPath,
    `--language=${langInfo.extractor}`,
    `--source-root=${repoPath}`,
    '--overwrite',
  ];

  if (config.threads) {
    args.push(`--threads=${config.threads}`);
  }

  if (config.ram) {
    args.push(`--ram=${config.ram}`);
  }

  // For languages that don't need a build, use --no-run-unnecessary-builds
  if (!langInfo.needsBuild) {
    args.push('--no-run-unnecessary-builds');
  }

  try {
    await execAsync(args.join(' '), {
      maxBuffer: 100 * 1024 * 1024,
      timeout: 30 * 60 * 1000, // 30 minute timeout
    });
    return { dbPath, success: true };
  } catch (error: any) {
    return {
      dbPath,
      success: false,
      error: error.message || 'Failed to create CodeQL database',
    };
  }
}

/**
 * Run CodeQL queries on a database
 */
export async function runCodeQLQueries(
  dbPath: string,
  outputDir: string,
  language: string,
  config: Partial<CodeQLConfig> = {}
): Promise<{
  run: AnalysisRun;
  results: CodeQLResult[];
  sarifPath: string;
}> {
  const startTime = Date.now();
  const sarifPath = path.join(outputDir, 'codeql-results.sarif');

  // Get query packs
  const queryPacks =
    config.queryPacks || DEFAULT_QUERY_PACKS[language.toLowerCase()] || [];

  if (queryPacks.length === 0) {
    const run: AnalysisRun = {
      tool: 'codeql',
      output: sarifPath,
      timestamp: new Date().toISOString(),
      duration_ms: 0,
      success: false,
      error: `No query packs available for language '${language}'`,
      raw_findings_count: 0,
    };
    return { run, results: [], sarifPath };
  }

  // Build the analyze command
  const args = [
    'codeql',
    'database',
    'analyze',
    dbPath,
    ...queryPacks,
    '--format=sarif-latest',
    `--output=${sarifPath}`,
    '--sarif-add-snippets',
    '--sarif-add-file-contents',
  ];

  if (config.threads) {
    args.push(`--threads=${config.threads}`);
  }

  if (config.timeout) {
    args.push(`--timeout=${config.timeout}`);
  }

  let success = true;
  let errorMessage: string | undefined;

  try {
    await execAsync(args.join(' '), {
      maxBuffer: 100 * 1024 * 1024,
      timeout: 60 * 60 * 1000, // 1 hour timeout for analysis
    });
  } catch (error: any) {
    success = false;
    errorMessage = error.message || 'Unknown error';
  }

  // Parse SARIF output
  let results: CodeQLResult[] = [];
  try {
    if (existsSync(sarifPath)) {
      const content = await fs.readFile(sarifPath, 'utf-8');
      const sarif = JSON.parse(content);
      results = extractResultsFromSarif(sarif);
    }
  } catch (parseError: any) {
    if (success) {
      success = false;
      errorMessage = `Failed to parse CodeQL output: ${parseError.message}`;
    }
  }

  const endTime = Date.now();

  const run: AnalysisRun = {
    tool: 'codeql',
    output: sarifPath,
    timestamp: new Date().toISOString(),
    duration_ms: endTime - startTime,
    success,
    error: errorMessage,
    raw_findings_count: results.length,
  };

  return { run, results, sarifPath };
}

/**
 * Extract results from SARIF format
 */
function extractResultsFromSarif(sarif: any): CodeQLResult[] {
  const results: CodeQLResult[] = [];

  for (const run of sarif.runs || []) {
    for (const result of run.results || []) {
      results.push({
        ruleId: result.ruleId || 'unknown',
        level: result.level || 'warning',
        message: result.message?.text || '',
        locations: result.locations || [],
        codeFlows: result.codeFlows,
        properties: result.properties,
      });
    }
  }

  return results;
}

/**
 * Map CodeQL severity to our severity
 */
export function mapCodeQLSeverity(level: string, securitySeverity?: string): FindingSeverity {
  // If security-severity is provided, use it
  if (securitySeverity) {
    const severity = parseFloat(securitySeverity);
    if (severity >= 9.0) return 'critical';
    if (severity >= 7.0) return 'high';
    if (severity >= 4.0) return 'medium';
    return 'low';
  }

  // Otherwise use level
  switch (level.toLowerCase()) {
    case 'error':
      return 'high';
    case 'warning':
      return 'medium';
    case 'note':
      return 'low';
    default:
      return 'medium';
  }
}

/**
 * Run full CodeQL analysis (database creation + queries)
 */
export async function runCodeQL(
  repoPath: string,
  outputDir: string,
  config: CodeQLConfig
): Promise<{
  run: AnalysisRun;
  results: CodeQLResult[];
  dbPaths: string[];
}> {
  const startTime = Date.now();
  const allResults: CodeQLResult[] = [];
  const dbPaths: string[] = [];
  let overallSuccess = true;
  let errors: string[] = [];

  // Create databases for each language
  for (const language of config.languages) {
    const langInfo = CODEQL_LANGUAGES[language.toLowerCase()];
    if (!langInfo?.supported) {
      continue;
    }

    // Skip languages that need build if we can't build
    if (langInfo.needsBuild) {
      // TODO: Attempt build detection and execution
      // For now, skip languages that require build
      continue;
    }

    const dbResult = await createCodeQLDatabase(repoPath, language, outputDir, config);
    if (!dbResult.success) {
      errors.push(`${language}: ${dbResult.error}`);
      continue;
    }

    dbPaths.push(dbResult.dbPath);

    // Run queries on the database
    const queryResult = await runCodeQLQueries(
      dbResult.dbPath,
      outputDir,
      language,
      config
    );

    if (!queryResult.run.success) {
      errors.push(`${language} queries: ${queryResult.run.error}`);
      overallSuccess = false;
    }

    allResults.push(...queryResult.results);
  }

  const endTime = Date.now();

  const run: AnalysisRun = {
    tool: 'codeql',
    output: path.join(outputDir, 'codeql-results.sarif'),
    timestamp: new Date().toISOString(),
    duration_ms: endTime - startTime,
    success: overallSuccess && errors.length === 0,
    error: errors.length > 0 ? errors.join('; ') : undefined,
    raw_findings_count: allResults.length,
  };

  return { run, results: allResults, dbPaths };
}

/**
 * Extract code flow (dataflow path) from a CodeQL result
 */
export function extractCodeFlow(result: CodeQLResult): Array<{
  path: string;
  line: number;
  message?: string;
}> {
  const flow: Array<{ path: string; line: number; message?: string }> = [];

  if (!result.codeFlows) {
    return flow;
  }

  for (const codeFlow of result.codeFlows) {
    for (const threadFlow of codeFlow.threadFlows) {
      for (const loc of threadFlow.locations) {
        const physLoc = loc.location.physicalLocation;
        flow.push({
          path: physLoc.artifactLocation.uri,
          line: physLoc.region.startLine,
          message: loc.location.message?.text,
        });
      }
    }
  }

  return flow;
}
