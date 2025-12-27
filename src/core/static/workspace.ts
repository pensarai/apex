/**
 * Static Analysis Workspace Management
 *
 * Creates and manages the workspace directory structure for static analysis runs.
 * Each run gets its own directory with subdirectories for artifacts, cache, and logs.
 */

import os from 'os';
import path from 'path';
import fs from 'fs/promises';
import { existsSync, mkdirSync } from 'fs';
import { nanoid } from 'nanoid';
import type { StaticAnalysisState, RepoInfo, StaticAnalysisStage } from './types';
import { STAGE_ORDER } from './types';

/**
 * Workspace directory structure
 */
export interface WorkspacePaths {
  /** Root directory of the workspace */
  root: string;
  /** Path to manifest.json (state contract) */
  manifest: string;
  /** Path to cloned/linked repo */
  repo: string;
  /** Artifacts directory */
  artifacts: {
    root: string;
    inventory: string;
    index: string;
    analysis: string;
    specs: string;
    findings: string;
    exploits: string;
    reports: string;
  };
  /** Cache directory (CodeQL DB, Joern CPG) */
  cache: string;
  /** Logs directory */
  logs: string;
  /** Scratchpad for JSONL and temp files */
  scratchpad: string;
}

/**
 * Get the base directory for static analysis runs
 */
export function getStaticRunsRoot(): string {
  return path.join(os.homedir(), '.pensar', 'static-runs');
}

/**
 * Generate a unique run ID
 */
export function generateRunId(): string {
  const timestamp = Date.now().toString(36);
  const random = nanoid(8);
  return `static_${timestamp}_${random}`;
}

/**
 * Get workspace paths for a given run ID
 */
export function getWorkspacePaths(runId: string): WorkspacePaths {
  const root = path.join(getStaticRunsRoot(), runId);
  const artifactsRoot = path.join(root, 'artifacts');

  return {
    root,
    manifest: path.join(root, 'manifest.json'),
    repo: path.join(root, 'repo'),
    artifacts: {
      root: artifactsRoot,
      inventory: path.join(artifactsRoot, 'inventory'),
      index: path.join(artifactsRoot, 'index'),
      analysis: path.join(artifactsRoot, 'analysis'),
      specs: path.join(artifactsRoot, 'specs'),
      findings: path.join(artifactsRoot, 'findings'),
      exploits: path.join(artifactsRoot, 'exploits'),
      reports: path.join(artifactsRoot, 'reports'),
    },
    cache: path.join(root, 'cache'),
    logs: path.join(root, 'logs'),
    scratchpad: path.join(root, 'scratchpad'),
  };
}

/**
 * Create workspace directory structure
 */
export async function createWorkspace(runId?: string): Promise<{
  runId: string;
  paths: WorkspacePaths;
}> {
  const id = runId || generateRunId();
  const paths = getWorkspacePaths(id);

  // Create all directories
  const dirsToCreate = [
    paths.root,
    paths.repo,
    paths.artifacts.root,
    paths.artifacts.inventory,
    paths.artifacts.index,
    paths.artifacts.analysis,
    paths.artifacts.specs,
    paths.artifacts.findings,
    paths.artifacts.exploits,
    paths.artifacts.reports,
    paths.cache,
    paths.logs,
    paths.scratchpad,
  ];

  for (const dir of dirsToCreate) {
    await fs.mkdir(dir, { recursive: true });
  }

  return { runId: id, paths };
}

/**
 * Initialize state for a new run
 */
export function createInitialState(runId: string, repo: RepoInfo): StaticAnalysisState {
  const now = new Date().toISOString();
  return {
    run_id: runId,
    repo,
    analysis_runs: [],
    candidates: [],
    findings: [],
    completed_stages: [],
    started_at: now,
    updated_at: now,
  };
}

/**
 * Save state to manifest.json
 */
export async function saveState(paths: WorkspacePaths, state: StaticAnalysisState): Promise<void> {
  state.updated_at = new Date().toISOString();
  await fs.writeFile(paths.manifest, JSON.stringify(state, null, 2));
}

/**
 * Load state from manifest.json
 */
export async function loadState(paths: WorkspacePaths): Promise<StaticAnalysisState | null> {
  try {
    const content = await fs.readFile(paths.manifest, 'utf-8');
    return JSON.parse(content) as StaticAnalysisState;
  } catch {
    return null;
  }
}

/**
 * Check if a workspace exists
 */
export function workspaceExists(runId: string): boolean {
  const paths = getWorkspacePaths(runId);
  return existsSync(paths.root) && existsSync(paths.manifest);
}

/**
 * List all static analysis runs
 */
export async function listRuns(): Promise<string[]> {
  const runsRoot = getStaticRunsRoot();
  try {
    const entries = await fs.readdir(runsRoot, { withFileTypes: true });
    return entries
      .filter(e => e.isDirectory() && e.name.startsWith('static_'))
      .map(e => e.name)
      .sort()
      .reverse(); // Most recent first
  } catch {
    return [];
  }
}

/**
 * Get the last completed stage for a run
 */
export function getLastCompletedStage(state: StaticAnalysisState): StaticAnalysisStage | null {
  if (state.completed_stages.length === 0) {
    return null;
  }
  // Return the last stage in order that was completed
  for (let i = STAGE_ORDER.length - 1; i >= 0; i--) {
    if (state.completed_stages.includes(STAGE_ORDER[i])) {
      return STAGE_ORDER[i];
    }
  }
  return null;
}

/**
 * Get the next stage to run
 */
export function getNextStage(state: StaticAnalysisState): StaticAnalysisStage | null {
  for (const stage of STAGE_ORDER) {
    if (!state.completed_stages.includes(stage)) {
      return stage;
    }
  }
  return null; // All stages completed
}

/**
 * Mark a stage as completed
 */
export function markStageCompleted(state: StaticAnalysisState, stage: StaticAnalysisStage): void {
  if (!state.completed_stages.includes(stage)) {
    state.completed_stages.push(stage);
  }
  state.current_stage = undefined;
}

/**
 * Mark a stage as in progress
 */
export function markStageInProgress(state: StaticAnalysisState, stage: StaticAnalysisStage): void {
  state.current_stage = stage;
}

/**
 * Get the stage number (1-8) for a given stage
 */
export function getStageNumber(stage: StaticAnalysisStage): number {
  return STAGE_ORDER.indexOf(stage) + 1;
}

/**
 * Clean up a workspace (delete all files)
 */
export async function cleanupWorkspace(runId: string): Promise<void> {
  const paths = getWorkspacePaths(runId);
  await fs.rm(paths.root, { recursive: true, force: true });
}

/**
 * Get log file path for an agent
 */
export function getAgentLogPath(paths: WorkspacePaths, stage: StaticAnalysisStage): string {
  return path.join(paths.logs, `${stage}.log`);
}

/**
 * Get JSONL results file path
 */
export function getResultsJsonlPath(paths: WorkspacePaths): string {
  return path.join(paths.scratchpad, 'analysis-results.jsonl');
}

/**
 * Append a line to the JSONL results file
 */
export async function appendToResultsJsonl(paths: WorkspacePaths, data: object): Promise<void> {
  const jsonlPath = getResultsJsonlPath(paths);
  await fs.appendFile(jsonlPath, JSON.stringify(data) + '\n');
}

/**
 * Read all lines from JSONL results file
 */
export async function readResultsJsonl<T>(paths: WorkspacePaths): Promise<T[]> {
  const jsonlPath = getResultsJsonlPath(paths);
  try {
    const content = await fs.readFile(jsonlPath, 'utf-8');
    return content
      .split('\n')
      .filter(line => line.trim())
      .map(line => JSON.parse(line) as T);
  } catch {
    return [];
  }
}

/**
 * Clone or link a repository to the workspace
 *
 * If URL is provided, clones the repository (URL takes precedence).
 * Otherwise, symlinks to the local path.
 */
export async function setupRepository(
  paths: WorkspacePaths,
  options: {
    url?: string;
    localPath?: string;
    ref?: string;
  }
): Promise<RepoInfo> {
  const { url, localPath, ref = 'HEAD' } = options;
  const { execSync } = await import('child_process');

  // Remove existing repo directory if it exists (from workspace creation)
  try {
    await fs.rm(paths.repo, { recursive: true, force: true });
  } catch {
    // Ignore if doesn't exist
  }

  if (url) {
    // Clone from URL (takes precedence if both URL and localPath provided)
    const cloneCmd = ref && ref !== 'HEAD'
      ? `git clone --branch ${ref} --depth 1 "${url}" "${paths.repo}"`
      : `git clone --depth 1 "${url}" "${paths.repo}"`;
    try {
      execSync(cloneCmd, { stdio: 'pipe' });
    } catch (error: any) {
      throw new Error(`Failed to clone repository: ${error.message}`);
    }
  } else if (localPath) {
    // Create symlink to local repo
    try {
      await fs.symlink(localPath, paths.repo, 'dir');
    } catch {
      // If symlink fails (Windows or same-device issue), copy instead
      await fs.cp(localPath, paths.repo, { recursive: true });
    }
  } else {
    throw new Error('Either url or localPath must be provided');
  }

  // Get commit SHA
  let commit: string;
  try {
    commit = execSync('git rev-parse HEAD', { cwd: paths.repo, encoding: 'utf-8' }).trim();
  } catch {
    commit = 'unknown';
  }

  return {
    root: paths.repo,
    url,
    ref,
    commit,
  };
}

/**
 * Get cache key for a commit (used for CodeQL DB, Joern CPG)
 */
export function getCacheKey(repoUrl: string | undefined, commit: string): string {
  const repoHash = repoUrl
    ? Buffer.from(repoUrl).toString('base64url').slice(0, 12)
    : 'local';
  return `${repoHash}_${commit.slice(0, 12)}`;
}

/**
 * Get path to cached CodeQL database
 */
export function getCodeQLCachePath(paths: WorkspacePaths, cacheKey: string): string {
  return path.join(paths.cache, `codeql_${cacheKey}`);
}

/**
 * Get path to cached Joern CPG
 */
export function getJoernCachePath(paths: WorkspacePaths, cacheKey: string): string {
  return path.join(paths.cache, `joern_${cacheKey}`);
}

/**
 * Save subagent messages (matching web agent pattern)
 */
export async function saveSubagentMessages(
  paths: WorkspacePaths,
  agentName: string,
  messages: any[],
  metadata?: Record<string, any>
): Promise<string> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const sanitizedName = agentName.toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const filename = `${sanitizedName}-${timestamp}.json`;
  const filepath = path.join(paths.logs, filename);

  const data = {
    agentName,
    timestamp: new Date().toISOString(),
    ...metadata,
    messages,
  };

  await fs.writeFile(filepath, JSON.stringify(data, null, 2));
  return filepath;
}
