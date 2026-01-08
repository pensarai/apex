/**
 * Tool Availability Detector
 *
 * Detects which external analysis tools are available on the system.
 * Supports graceful degradation when tools are missing.
 */

import { execSync, exec } from 'child_process';
import { promisify } from 'util';
import type { ToolAvailability } from '../types';

const execAsync = promisify(exec);

/**
 * Check if a command exists on the system
 */
async function commandExists(command: string): Promise<boolean> {
  try {
    const { stdout } = await execAsync(`which ${command}`);
    return stdout.trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * Get version string for a tool
 */
async function getToolVersion(
  command: string,
  versionFlag: string = '--version'
): Promise<string | undefined> {
  try {
    const { stdout } = await execAsync(`${command} ${versionFlag} 2>&1`);
    // Extract first line and clean up
    const firstLine = stdout.trim().split('\n')[0];
    // Extract version number if present
    const versionMatch = firstLine?.match(/(\d+\.\d+(\.\d+)?)/);
    return versionMatch ? versionMatch[1] : firstLine;
  } catch {
    return undefined;
  }
}

/**
 * Detect Semgrep availability
 */
export async function detectSemgrep(): Promise<{ available: boolean; version?: string }> {
  const exists = await commandExists('semgrep');
  if (!exists) {
    return { available: false };
  }
  const version = await getToolVersion('semgrep', '--version');
  return { available: true, version };
}

/**
 * Detect CodeQL availability
 */
export async function detectCodeQL(): Promise<{ available: boolean; version?: string }> {
  const exists = await commandExists('codeql');
  if (!exists) {
    return { available: false };
  }
  const version = await getToolVersion('codeql', 'version');
  return { available: true, version };
}

/**
 * Detect Joern availability
 */
export async function detectJoern(): Promise<{ available: boolean; version?: string }> {
  // Joern can be installed as 'joern' or 'joern-parse'
  const joernExists = await commandExists('joern');
  const joernParseExists = await commandExists('joern-parse');

  if (!joernExists && !joernParseExists) {
    return { available: false };
  }

  const version = await getToolVersion(
    joernExists ? 'joern' : 'joern-parse',
    '--version'
  );
  return { available: true, version };
}

/**
 * Detect TruffleHog availability
 */
export async function detectTrufflehog(): Promise<{ available: boolean; version?: string }> {
  const exists = await commandExists('trufflehog');
  if (!exists) {
    return { available: false };
  }
  const version = await getToolVersion('trufflehog', '--version');
  return { available: true, version };
}

/**
 * Detect Grype (vulnerability scanner) availability
 */
export async function detectGrype(): Promise<{ available: boolean; version?: string }> {
  const exists = await commandExists('grype');
  if (!exists) {
    return { available: false };
  }
  const version = await getToolVersion('grype', 'version');
  return { available: true, version };
}

/**
 * Detect all available tools
 */
export async function detectAvailableTools(): Promise<ToolAvailability> {
  const [semgrep, codeql, joern, trufflehog, grype] = await Promise.all([
    detectSemgrep(),
    detectCodeQL(),
    detectJoern(),
    detectTrufflehog(),
    detectGrype(),
  ]);

  return {
    semgrep,
    codeql,
    joern,
    trufflehog,
    grype,
  };
}

/**
 * Check if minimum required tools are available
 * At minimum, we need Semgrep (easiest to install)
 */
export function hasMinimumTools(availability: ToolAvailability): boolean {
  return availability.semgrep.available;
}

/**
 * Get a summary of available tools
 */
export function getToolSummary(availability: ToolAvailability): string {
  const lines: string[] = ['Tool Availability:'];

  const tools = [
    { name: 'Semgrep', status: availability.semgrep },
    { name: 'CodeQL', status: availability.codeql },
    { name: 'Joern', status: availability.joern },
    { name: 'TruffleHog', status: availability.trufflehog },
    { name: 'Grype', status: availability.grype },
  ];

  for (const tool of tools) {
    const statusIcon = tool.status.available ? '✓' : '✗';
    const versionStr = tool.status.version ? ` (${tool.status.version})` : '';
    lines.push(`  ${statusIcon} ${tool.name}${versionStr}`);
  }

  return lines.join('\n');
}

/**
 * Get installation instructions for missing tools
 */
export function getInstallInstructions(availability: ToolAvailability): string[] {
  const instructions: string[] = [];

  if (!availability.semgrep.available) {
    instructions.push('Semgrep: pip install semgrep');
  }

  if (!availability.codeql.available) {
    instructions.push(
      'CodeQL: Download from https://github.com/github/codeql-cli-binaries'
    );
  }

  if (!availability.joern.available) {
    instructions.push('Joern: https://joern.io/docs/installation');
  }

  if (!availability.trufflehog.available) {
    instructions.push('TruffleHog: brew install trufflehog (or from GitHub releases)');
  }

  if (!availability.grype.available) {
    instructions.push('Grype: brew install grype (or curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh)');
  }

  return instructions;
}

/**
 * Get languages supported by available tools
 */
export function getSupportedLanguages(availability: ToolAvailability): {
  semgrep: string[];
  codeql: string[];
  joern: string[];
} {
  // These are the commonly supported languages by each tool
  return {
    semgrep: availability.semgrep.available
      ? [
          'python',
          'javascript',
          'typescript',
          'java',
          'go',
          'ruby',
          'php',
          'c',
          'cpp',
          'csharp',
          'kotlin',
          'scala',
          'rust',
          'swift',
        ]
      : [],
    codeql: availability.codeql.available
      ? ['python', 'javascript', 'typescript', 'java', 'go', 'ruby', 'csharp', 'cpp']
      : [],
    joern: availability.joern.available
      ? ['c', 'cpp', 'java', 'javascript', 'python', 'php', 'go']
      : [],
  };
}
