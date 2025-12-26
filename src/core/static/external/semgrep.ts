/**
 * Semgrep Integration
 *
 * Wrapper for running Semgrep static analysis.
 * Semgrep is the "always-on" tool that's easy to install and works with most languages.
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import type { AnalysisRun, FindingSeverity } from '../types';

const execAsync = promisify(exec);

/**
 * Semgrep configuration
 */
export interface SemgrepConfig {
  /** Rule configs to use (default: auto + security-audit) */
  rules?: string[];
  /** Patterns to exclude */
  exclude?: string[];
  /** Per-file timeout in seconds */
  timeout?: number;
  /** Maximum file size in bytes */
  maxTargetBytes?: number;
  /** Maximum memory in MB */
  maxMemory?: number;
  /** Number of jobs (parallel scanning) */
  jobs?: number;
  /** Severity threshold (info, warning, error) */
  severity?: string[];
}

/**
 * Semgrep finding from JSON output
 */
export interface SemgrepFinding {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: {
    message: string;
    severity: string;
    metadata: {
      cwe?: string[];
      owasp?: string[];
      category?: string;
      confidence?: string;
      impact?: string;
      likelihood?: string;
      references?: string[];
      source?: string;
      technology?: string[];
    };
    fix?: string;
    lines: string;
  };
}

/**
 * Semgrep JSON output structure
 */
export interface SemgrepOutput {
  version: string;
  results: SemgrepFinding[];
  errors: Array<{
    code: number;
    level: string;
    message: string;
    path?: string;
    type: string;
  }>;
  paths: {
    scanned: string[];
    skipped?: Array<{ path: string; reason: string }>;
  };
}

/**
 * Default Semgrep configuration
 */
const DEFAULT_CONFIG: SemgrepConfig = {
  rules: ['auto', 'p/security-audit'],
  exclude: [
    'node_modules',
    'vendor',
    'venv',
    '.venv',
    '__pycache__',
    '.git',
    'dist',
    'build',
    'target',
    '*.min.js',
    '*.bundle.js',
  ],
  timeout: 30,
  maxTargetBytes: 1024 * 1024, // 1MB
  maxMemory: 4096, // 4GB
  jobs: 4,
  severity: ['ERROR', 'WARNING'],
};

/**
 * Build Semgrep command arguments
 */
function buildSemgrepArgs(repoPath: string, outputPath: string, config: SemgrepConfig): string[] {
  const args: string[] = ['semgrep', 'scan', '--json', '-o', outputPath];

  // Add rules
  const rules = config.rules || DEFAULT_CONFIG.rules!;
  for (const rule of rules) {
    if (rule.startsWith('p/') || rule === 'auto') {
      args.push('--config', rule);
    } else {
      args.push('--config', rule);
    }
  }

  // Add excludes
  const excludes = config.exclude || DEFAULT_CONFIG.exclude!;
  for (const pattern of excludes) {
    args.push('--exclude', pattern);
  }

  // Add timeout
  args.push('--timeout', String(config.timeout || DEFAULT_CONFIG.timeout));

  // Add max target bytes
  args.push(
    '--max-target-bytes',
    String(config.maxTargetBytes || DEFAULT_CONFIG.maxTargetBytes)
  );

  // Add max memory
  args.push('--max-memory', String(config.maxMemory || DEFAULT_CONFIG.maxMemory));

  // Add jobs
  args.push('--jobs', String(config.jobs || DEFAULT_CONFIG.jobs));

  // Add severity filter
  const severities = config.severity || DEFAULT_CONFIG.severity!;
  for (const sev of severities) {
    args.push('--severity', sev);
  }

  // Add quiet flag to reduce noise
  args.push('--quiet');

  // Add the target path
  args.push(repoPath);

  return args;
}

/**
 * Map Semgrep severity to our severity
 */
export function mapSemgrepSeverity(semgrepSeverity: string): FindingSeverity {
  switch (semgrepSeverity.toUpperCase()) {
    case 'ERROR':
      return 'high';
    case 'WARNING':
      return 'medium';
    case 'INFO':
      return 'low';
    default:
      return 'medium';
  }
}

/**
 * Extract CWE IDs from Semgrep metadata
 */
export function extractCWEs(finding: SemgrepFinding): string[] {
  const cwes: string[] = [];

  if (finding.extra.metadata.cwe) {
    for (const cwe of finding.extra.metadata.cwe) {
      // Normalize CWE format (e.g., "CWE-79" or "79")
      const match = cwe.match(/(?:CWE-)?(\d+)/i);
      if (match) {
        cwes.push(`CWE-${match[1]}`);
      }
    }
  }

  return cwes;
}

/**
 * Run Semgrep analysis on a repository
 */
export async function runSemgrep(
  repoPath: string,
  outputDir: string,
  config: Partial<SemgrepConfig> = {}
): Promise<{
  run: AnalysisRun;
  findings: SemgrepFinding[];
  output: SemgrepOutput;
}> {
  const startTime = Date.now();
  const outputPath = path.join(outputDir, 'semgrep.json');
  const mergedConfig = { ...DEFAULT_CONFIG, ...config };

  const args = buildSemgrepArgs(repoPath, outputPath, mergedConfig);
  const command = args.join(' ');

  let success = true;
  let errorMessage: string | undefined;

  try {
    // Run Semgrep (it may exit with non-zero if findings exist)
    await execAsync(command, {
      maxBuffer: 100 * 1024 * 1024, // 100MB buffer
      timeout: 30 * 60 * 1000, // 30 minute timeout
    });
  } catch (error: any) {
    // Semgrep exits with code 1 when findings are present, which is expected
    if (error.code !== 1) {
      success = false;
      errorMessage = error.message || 'Unknown error';
    }
  }

  // Parse output
  let output: SemgrepOutput;
  let findings: SemgrepFinding[] = [];

  try {
    const content = await fs.readFile(outputPath, 'utf-8');
    output = JSON.parse(content) as SemgrepOutput;
    findings = output.results || [];
  } catch (parseError: any) {
    success = false;
    errorMessage = `Failed to parse Semgrep output: ${parseError.message}`;
    output = {
      version: '',
      results: [],
      errors: [{ code: -1, level: 'error', message: errorMessage, type: 'ParseError' }],
      paths: { scanned: [] },
    };
  }

  const endTime = Date.now();

  const run: AnalysisRun = {
    tool: 'semgrep',
    output: outputPath,
    timestamp: new Date().toISOString(),
    duration_ms: endTime - startTime,
    success,
    error: errorMessage,
    raw_findings_count: findings.length,
  };

  return { run, findings, output };
}

/**
 * Get Semgrep rule packs for specific vulnerability categories
 */
export function getRulePacksForCategory(category: string): string[] {
  const categoryMap: Record<string, string[]> = {
    injection: ['p/injection', 'p/sql-injection', 'p/command-injection'],
    xss: ['p/xss', 'p/dom-xss'],
    auth: ['p/auth', 'p/jwt', 'p/session'],
    crypto: ['p/crypto', 'p/secrets'],
    deserialization: ['p/deserialization', 'p/insecure-deserialization'],
    ssrf: ['p/ssrf'],
    xxe: ['p/xxe'],
    path_traversal: ['p/path-traversal'],
    default: ['auto', 'p/security-audit'],
  };

  return categoryMap[category] || categoryMap.default;
}

/**
 * Parse a Semgrep SARIF output file
 */
export async function parseSemgrepSarif(sarifPath: string): Promise<SemgrepFinding[]> {
  try {
    const content = await fs.readFile(sarifPath, 'utf-8');
    const sarif = JSON.parse(content);

    const findings: SemgrepFinding[] = [];

    for (const run of sarif.runs || []) {
      for (const result of run.results || []) {
        const location = result.locations?.[0]?.physicalLocation;
        if (!location) continue;

        findings.push({
          check_id: result.ruleId || 'unknown',
          path: location.artifactLocation?.uri || '',
          start: {
            line: location.region?.startLine || 1,
            col: location.region?.startColumn || 1,
          },
          end: {
            line: location.region?.endLine || location.region?.startLine || 1,
            col: location.region?.endColumn || 1,
          },
          extra: {
            message: result.message?.text || '',
            severity: result.level || 'warning',
            metadata: {
              cwe: result.properties?.cwe || [],
              owasp: result.properties?.owasp || [],
            },
            lines: '',
          },
        });
      }
    }

    return findings;
  } catch {
    return [];
  }
}
