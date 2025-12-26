/**
 * TruffleHog Integration
 *
 * Wrapper for running TruffleHog secrets detection.
 * Scans for exposed credentials, API keys, and other sensitive data.
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import type { AnalysisRun, FindingSeverity } from '../types';

const execAsync = promisify(exec);

/**
 * TruffleHog configuration
 */
export interface TrufflehogConfig {
  /** Maximum depth for git history scan */
  maxDepth?: number;
  /** Include verification of detected secrets */
  verify?: boolean;
  /** Only show verified secrets */
  onlyVerified?: boolean;
  /** Exclude specific paths */
  exclude?: string[];
  /** Include regex for paths */
  include?: string[];
  /** Concurrency level */
  concurrency?: number;
}

/**
 * TruffleHog finding structure
 */
export interface TrufflehogFinding {
  SourceMetadata: {
    Data: {
      Git?: {
        commit: string;
        file: string;
        email: string;
        repository: string;
        timestamp: string;
        line: number;
      };
      Filesystem?: {
        file: string;
        line?: number;
      };
    };
  };
  SourceID: number;
  SourceType: number;
  SourceName: string;
  DetectorType: number;
  DetectorName: string;
  DecoderName: string;
  Verified: boolean;
  Raw: string;
  RawV2?: string;
  Redacted: string;
  ExtraData?: Record<string, string>;
  StructuredData?: {
    Github?: { link?: string };
    TLS?: { issuer?: string };
  };
}

/**
 * Default TruffleHog configuration
 */
const DEFAULT_CONFIG: TrufflehogConfig = {
  maxDepth: 100,
  verify: true,
  onlyVerified: false,
  concurrency: 10,
  exclude: [
    'node_modules',
    'vendor',
    '.git/objects',
    '__pycache__',
    'dist',
    'build',
    '*.min.js',
  ],
};

/**
 * Detector type to human-readable name mapping
 */
const DETECTOR_NAMES: Record<number, string> = {
  1: 'AWS',
  2: 'Github',
  3: 'GCP',
  4: 'Stripe',
  5: 'Slack',
  6: 'Mailchimp',
  7: 'Twilio',
  8: 'SendGrid',
  9: 'Heroku',
  10: 'Atlassian',
  11: 'PrivateKey',
  12: 'Password',
  13: 'APIKey',
  14: 'JWT',
  15: 'Basic Auth',
  16: 'OAuth',
  17: 'Database',
  18: 'SSH Key',
  19: 'Azure',
  20: 'DigitalOcean',
};

/**
 * Check if TruffleHog is available
 */
export async function isTrufflehogAvailable(): Promise<boolean> {
  try {
    await execAsync('trufflehog --version');
    return true;
  } catch {
    return false;
  }
}

/**
 * Run TruffleHog secrets scan on a repository
 */
export async function runTrufflehog(
  repoPath: string,
  outputDir: string,
  config: Partial<TrufflehogConfig> = {}
): Promise<{
  run: AnalysisRun;
  findings: TrufflehogFinding[];
}> {
  const startTime = Date.now();
  const outputPath = path.join(outputDir, 'trufflehog.json');
  const mergedConfig = { ...DEFAULT_CONFIG, ...config };

  // Build command for filesystem scan
  const args = [
    'trufflehog',
    'filesystem',
    repoPath,
    '--json',
    `--concurrency=${mergedConfig.concurrency}`,
  ];

  if (mergedConfig.verify) {
    args.push('--verify');
  }

  if (mergedConfig.onlyVerified) {
    args.push('--only-verified');
  }

  // Add excludes
  for (const pattern of mergedConfig.exclude || []) {
    args.push('--exclude-paths', pattern);
  }

  let success = true;
  let errorMessage: string | undefined;
  let stdout = '';

  try {
    const result = await execAsync(args.join(' '), {
      maxBuffer: 100 * 1024 * 1024,
      timeout: 30 * 60 * 1000, // 30 minute timeout
    });
    stdout = result.stdout;
  } catch (error: any) {
    // TruffleHog exits with non-zero when secrets are found
    if (error.stdout) {
      stdout = error.stdout;
    } else {
      success = false;
      errorMessage = error.message || 'Unknown error';
    }
  }

  // Parse NDJSON output (one JSON object per line)
  const findings = parseNDJSON(stdout);

  // Write findings to JSON file
  await fs.writeFile(outputPath, JSON.stringify(findings, null, 2));

  const endTime = Date.now();

  const run: AnalysisRun = {
    tool: 'secrets',
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
 * Run TruffleHog git scan (includes history)
 */
export async function runTrufflehogGit(
  repoPath: string,
  outputDir: string,
  config: Partial<TrufflehogConfig> = {}
): Promise<{
  run: AnalysisRun;
  findings: TrufflehogFinding[];
}> {
  const startTime = Date.now();
  const outputPath = path.join(outputDir, 'trufflehog-git.json');
  const mergedConfig = { ...DEFAULT_CONFIG, ...config };

  const args = [
    'trufflehog',
    'git',
    `file://${repoPath}`,
    '--json',
    `--concurrency=${mergedConfig.concurrency}`,
  ];

  if (mergedConfig.maxDepth) {
    args.push(`--max-depth=${mergedConfig.maxDepth}`);
  }

  if (mergedConfig.verify) {
    args.push('--verify');
  }

  if (mergedConfig.onlyVerified) {
    args.push('--only-verified');
  }

  let success = true;
  let errorMessage: string | undefined;
  let stdout = '';

  try {
    const result = await execAsync(args.join(' '), {
      maxBuffer: 100 * 1024 * 1024,
      timeout: 60 * 60 * 1000, // 1 hour timeout for git history
    });
    stdout = result.stdout;
  } catch (error: any) {
    if (error.stdout) {
      stdout = error.stdout;
    } else {
      success = false;
      errorMessage = error.message || 'Unknown error';
    }
  }

  const findings = parseNDJSON(stdout);
  await fs.writeFile(outputPath, JSON.stringify(findings, null, 2));

  const endTime = Date.now();

  const run: AnalysisRun = {
    tool: 'secrets',
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
 * Parse NDJSON (newline-delimited JSON) output
 */
function parseNDJSON(output: string): TrufflehogFinding[] {
  const findings: TrufflehogFinding[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || !trimmed.startsWith('{')) {
      continue;
    }

    try {
      const parsed = JSON.parse(trimmed) as TrufflehogFinding;
      if (parsed.DetectorName || parsed.DetectorType) {
        findings.push(parsed);
      }
    } catch {
      // Skip invalid JSON lines
    }
  }

  return findings;
}

/**
 * Get severity for a secret finding
 */
export function getSecretSeverity(finding: TrufflehogFinding): FindingSeverity {
  // Verified secrets are more critical
  if (finding.Verified) {
    return 'critical';
  }

  // High-value targets
  const highValueDetectors = [
    'AWS',
    'GCP',
    'Azure',
    'PrivateKey',
    'SSH Key',
    'Database',
  ];

  const detectorName =
    finding.DetectorName || DETECTOR_NAMES[finding.DetectorType] || 'Unknown';

  if (highValueDetectors.some((d) => detectorName.includes(d))) {
    return 'high';
  }

  // API keys and tokens
  if (
    detectorName.includes('API') ||
    detectorName.includes('Token') ||
    detectorName.includes('Key')
  ) {
    return 'high';
  }

  return 'medium';
}

/**
 * Get CWE for a secret finding
 */
export function getSecretCWE(finding: TrufflehogFinding): string[] {
  const cwes: string[] = ['CWE-798']; // Use of Hard-coded Credentials

  if (finding.DetectorName?.includes('PrivateKey') || finding.DetectorName?.includes('SSH')) {
    cwes.push('CWE-321'); // Use of Hard-coded Cryptographic Key
  }

  if (finding.DetectorName?.includes('Password')) {
    cwes.push('CWE-259'); // Use of Hard-coded Password
  }

  return cwes;
}

/**
 * Get file location from finding
 */
export function getSecretLocation(finding: TrufflehogFinding): {
  file: string;
  line?: number;
  commit?: string;
} {
  const gitData = finding.SourceMetadata?.Data?.Git;
  const fsData = finding.SourceMetadata?.Data?.Filesystem;

  if (gitData) {
    return {
      file: gitData.file,
      line: gitData.line,
      commit: gitData.commit,
    };
  }

  if (fsData) {
    return {
      file: fsData.file,
      line: fsData.line,
    };
  }

  return { file: 'unknown' };
}

/**
 * Format a TruffleHog finding for display
 */
export function formatSecretFinding(finding: TrufflehogFinding): string {
  const location = getSecretLocation(finding);
  const detectorName =
    finding.DetectorName || DETECTOR_NAMES[finding.DetectorType] || 'Unknown';
  const verified = finding.Verified ? ' [VERIFIED]' : '';

  return `${detectorName}${verified}: ${location.file}${
    location.line ? `:${location.line}` : ''
  }`;
}
