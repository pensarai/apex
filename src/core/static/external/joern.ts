/**
 * Joern Integration
 *
 * Wrapper for running Joern code property graph (CPG) analysis.
 * Joern excels at custom dataflow queries and C/C++ analysis.
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { existsSync } from 'fs';
import type { AnalysisRun, FindingSeverity } from '../types';

const execAsync = promisify(exec);

/**
 * Joern configuration
 */
export interface JoernConfig {
  /** Languages to analyze */
  languages: string[];
  /** Custom query scripts */
  customQueries?: string[];
  /** Memory limit in MB */
  maxMemory?: number;
  /** Timeout per query in seconds */
  timeout?: number;
}

/**
 * Joern finding structure
 */
export interface JoernFinding {
  ruleId: string;
  title: string;
  description: string;
  severity: string;
  location: {
    filename: string;
    lineNumber: number;
    columnNumber?: number;
    methodFullName?: string;
  };
  dataflow?: Array<{
    filename: string;
    lineNumber: number;
    code: string;
  }>;
  cwe?: string[];
}

/**
 * Supported Joern languages
 */
export const JOERN_LANGUAGES: Record<
  string,
  { supported: boolean; parser: string }
> = {
  c: { supported: true, parser: 'c' },
  cpp: { supported: true, parser: 'c' },
  java: { supported: true, parser: 'javasrc' },
  javascript: { supported: true, parser: 'jssrc' },
  typescript: { supported: true, parser: 'jssrc' },
  python: { supported: true, parser: 'pythonsrc' },
  php: { supported: true, parser: 'php' },
  go: { supported: true, parser: 'gosrc' },
};

/**
 * Default security queries for Joern
 */
const DEFAULT_QUERIES = `
// SQL Injection
def sqlInjectionSinks = cpg.call.name("execute.*|query|raw").argument.order(1)
def sqlSources = cpg.parameter.filter(_.method.isPublic)
sqlSources.reachableBy(sqlInjectionSinks).l.map(f =>
  s"SQLi: \${f.location.filename}:\${f.lineNumber}")

// Command Injection
def cmdSinks = cpg.call.name("system|exec.*|popen|spawn").argument.order(1)
def cmdSources = cpg.parameter.filter(_.method.isPublic)
cmdSources.reachableBy(cmdSinks).l.map(f =>
  s"CmdInj: \${f.location.filename}:\${f.lineNumber}")

// Path Traversal
def pathSinks = cpg.call.name("open|fopen|readFile|writeFile").argument.order(1)
def pathSources = cpg.parameter.filter(_.method.isPublic)
pathSources.reachableBy(pathSinks).l.map(f =>
  s"PathTraversal: \${f.location.filename}:\${f.lineNumber}")
`;

/**
 * Check if Joern is available
 */
export async function isJoernAvailable(): Promise<boolean> {
  try {
    await execAsync('joern --version 2>/dev/null || joern-parse --version 2>/dev/null');
    return true;
  } catch {
    return false;
  }
}

/**
 * Create a Joern Code Property Graph (CPG)
 */
export async function createJoernCPG(
  repoPath: string,
  outputDir: string,
  languages: string[],
  config: Partial<JoernConfig> = {}
): Promise<{ cpgPath: string; success: boolean; error?: string }> {
  const cpgPath = path.join(outputDir, 'cpg.bin');

  // Determine which parser to use based on languages
  // For mixed repos, we'll create multiple CPGs
  const parsers = languages
    .map((lang) => JOERN_LANGUAGES[lang.toLowerCase()]?.parser)
    .filter((p): p is string => !!p);

  if (parsers.length === 0) {
    return {
      cpgPath: '',
      success: false,
      error: 'No supported languages found for Joern',
    };
  }

  // Use the first supported parser (Joern doesn't support multiple at once easily)
  const parser = parsers[0];

  const args = ['joern-parse', '--output', cpgPath, repoPath];

  // Add language-specific options
  if (parser === 'c') {
    args.push('--language', 'c');
  } else if (parser === 'javasrc') {
    args.push('--language', 'javasrc');
  } else if (parser === 'jssrc') {
    args.push('--language', 'jssrc');
  } else if (parser === 'pythonsrc') {
    args.push('--language', 'pythonsrc');
  }

  try {
    const env = { ...process.env } as NodeJS.ProcessEnv;
    if (config.maxMemory) {
      env.JAVA_OPTS = `-Xmx${config.maxMemory}m`;
    }

    await execAsync(args.join(' '), {
      maxBuffer: 100 * 1024 * 1024,
      timeout: 30 * 60 * 1000, // 30 minute timeout
      env,
    });

    return { cpgPath, success: true };
  } catch (error: any) {
    return {
      cpgPath,
      success: false,
      error: error.message || 'Failed to create Joern CPG',
    };
  }
}

/**
 * Run Joern queries on a CPG
 */
export async function runJoernQueries(
  cpgPath: string,
  outputDir: string,
  customQueries?: string,
  config: Partial<JoernConfig> = {}
): Promise<{
  run: AnalysisRun;
  findings: JoernFinding[];
}> {
  const startTime = Date.now();
  const outputPath = path.join(outputDir, 'joern-results.json');
  const queryPath = path.join(outputDir, 'joern-queries.sc');

  // Write queries to file
  const queries = customQueries || DEFAULT_QUERIES;
  await fs.writeFile(queryPath, queries);

  // Build the Joern command
  // Joern interactive mode with script execution
  const args = [
    'joern',
    '--script',
    queryPath,
    '--param',
    `cpgPath=${cpgPath}`,
  ];

  let success = true;
  let errorMessage: string | undefined;
  let stdout = '';

  try {
    const env = { ...process.env } as NodeJS.ProcessEnv;
    if (config.maxMemory) {
      env.JAVA_OPTS = `-Xmx${config.maxMemory}m`;
    }

    const result = await execAsync(args.join(' '), {
      maxBuffer: 100 * 1024 * 1024,
      timeout: config.timeout ? config.timeout * 1000 : 30 * 60 * 1000,
      env,
    });
    stdout = result.stdout;
  } catch (error: any) {
    success = false;
    errorMessage = error.message || 'Unknown error';
    stdout = error.stdout || '';
  }

  // Parse output into findings
  const findings = parseJoernOutput(stdout);

  // Write findings to JSON
  await fs.writeFile(outputPath, JSON.stringify(findings, null, 2));

  const endTime = Date.now();

  const run: AnalysisRun = {
    tool: 'joern',
    output: outputPath,
    timestamp: new Date().toISOString(),
    duration_ms: endTime - startTime,
    success,
    error: errorMessage,
    raw_findings_count: findings.length,
  };

  return { run, findings };
}

/**
 * Parse Joern console output into findings
 */
function parseJoernOutput(output: string): JoernFinding[] {
  const findings: JoernFinding[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    // Parse our custom output format: "RuleType: filename:lineNumber"
    const match = line.match(/^(\w+):\s+(.+):(\d+)$/);
    if (match) {
      const [, ruleType, filename, lineNum] = match;
      findings.push({
        ruleId: ruleType!,
        title: getRuleTitleFromType(ruleType!),
        description: getRuleDescriptionFromType(ruleType!),
        severity: getRuleSeverityFromType(ruleType!),
        location: {
          filename: filename!,
          lineNumber: parseInt(lineNum!, 10),
        },
        cwe: getCWEFromRuleType(ruleType!),
      });
    }

    // Also try to parse JSON output
    try {
      if (line.trim().startsWith('{')) {
        const parsed = JSON.parse(line);
        if (parsed.ruleId && parsed.location) {
          findings.push(parsed as JoernFinding);
        }
      }
    } catch {
      // Not JSON, skip
    }
  }

  return findings;
}

/**
 * Get human-readable title from rule type
 */
function getRuleTitleFromType(ruleType: string): string {
  const titles: Record<string, string> = {
    SQLi: 'SQL Injection',
    CmdInj: 'Command Injection',
    PathTraversal: 'Path Traversal',
    XSS: 'Cross-Site Scripting',
    SSRF: 'Server-Side Request Forgery',
    Deserialization: 'Insecure Deserialization',
    XXE: 'XML External Entity',
  };
  return titles[ruleType] || ruleType;
}

/**
 * Get description from rule type
 */
function getRuleDescriptionFromType(ruleType: string): string {
  const descriptions: Record<string, string> = {
    SQLi: 'User-controlled data reaches a SQL query without proper sanitization',
    CmdInj: 'User-controlled data reaches a command execution function',
    PathTraversal: 'User-controlled data reaches a file path operation',
    XSS: 'User-controlled data is rendered in HTML without escaping',
    SSRF: 'User-controlled data is used in a server-side HTTP request',
    Deserialization: 'User-controlled data is deserialized without validation',
    XXE: 'XML parser is configured to process external entities',
  };
  return descriptions[ruleType] || 'Potential security vulnerability detected';
}

/**
 * Get severity from rule type
 */
function getRuleSeverityFromType(ruleType: string): string {
  const severities: Record<string, string> = {
    SQLi: 'high',
    CmdInj: 'critical',
    PathTraversal: 'high',
    XSS: 'medium',
    SSRF: 'high',
    Deserialization: 'high',
    XXE: 'high',
  };
  return severities[ruleType] || 'medium';
}

/**
 * Get CWE from rule type
 */
function getCWEFromRuleType(ruleType: string): string[] {
  const cwes: Record<string, string[]> = {
    SQLi: ['CWE-89'],
    CmdInj: ['CWE-78'],
    PathTraversal: ['CWE-22'],
    XSS: ['CWE-79'],
    SSRF: ['CWE-918'],
    Deserialization: ['CWE-502'],
    XXE: ['CWE-611'],
  };
  return cwes[ruleType] || [];
}

/**
 * Map Joern severity to our severity
 */
export function mapJoernSeverity(joernSeverity: string): FindingSeverity {
  switch (joernSeverity.toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'medium';
  }
}

/**
 * Run full Joern analysis (CPG creation + queries)
 */
export async function runJoern(
  repoPath: string,
  outputDir: string,
  config: JoernConfig
): Promise<{
  run: AnalysisRun;
  findings: JoernFinding[];
  cpgPath?: string;
}> {
  const startTime = Date.now();

  // Create CPG
  const cpgResult = await createJoernCPG(repoPath, outputDir, config.languages, config);
  if (!cpgResult.success) {
    const run: AnalysisRun = {
      tool: 'joern',
      output: '',
      timestamp: new Date().toISOString(),
      duration_ms: Date.now() - startTime,
      success: false,
      error: cpgResult.error,
      raw_findings_count: 0,
    };
    return { run, findings: [] };
  }

  // Run queries
  const queryResult = await runJoernQueries(
    cpgResult.cpgPath,
    outputDir,
    config.customQueries?.join('\n'),
    config
  );

  return {
    run: queryResult.run,
    findings: queryResult.findings,
    cpgPath: cpgResult.cpgPath,
  };
}

/**
 * Generate a custom Joern query for a specific taint flow
 */
export function generateTaintQuery(
  sources: string[],
  sinks: string[],
  sanitizers: string[] = []
): string {
  const sourcePattern = sources.join('|');
  const sinkPattern = sinks.join('|');

  let query = `
// Custom taint flow query
def sources = cpg.call.name("${sourcePattern}").argument
def sinks = cpg.call.name("${sinkPattern}").argument
`;

  if (sanitizers.length > 0) {
    const sanitizerPattern = sanitizers.join('|');
    query += `
def sanitizers = cpg.call.name("${sanitizerPattern}")
sinks.reachableByFlows(sources).passes(!sanitizers).l
`;
  } else {
    query += `
sinks.reachableByFlows(sources).l
`;
  }

  return query;
}
