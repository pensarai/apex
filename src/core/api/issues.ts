/**
 * REST API client for the Pensar Issues API.
 *
 * Wraps the /{proxy+} endpoints exposed by the console's issues-api Lambda.
 * Auth is handled via Bearer token (WorkOS JWT) or API key, with an
 * X-Workspace-Id header for JWT auth.
 */

import { getPensarApiUrl } from "./constants";
import { config } from "../config";
import { ensureValidToken } from "../auth/token";

// ── Types ────────────────────────────────────────────────────────────

export interface ProjectSummary {
  id: string;
  name: string;
  source?: string;
}

export interface ScanSummary {
  id: string;
  label: string;
  status: string;
  scanType?: string;
  branch?: string;
  startedAt?: string;
  completedAt?: string;
}

export interface ScanDetail extends ScanSummary {
  projectId: string;
  projectName: string;
  errorMessage?: string;
  issuesFound: number;
  reportReady: boolean;
}

export interface IssueSummary {
  id: string;
  title: string;
  severity: string;
  status: string;
  location: string;
}

export interface IssueDetail extends IssueSummary {
  description?: string;
  lineRange?: string;
  cwe?: string;
  branch?: string;
  endpoint?: string;
  poc?: string;
  projectId: string;
  projectName: string;
  createdAt: string;
}

export interface UpdateIssueResult {
  success: boolean;
  issue: {
    id: string;
    name: string;
    status: string;
    severity: string;
    userFlaggedFalsePositive: boolean;
    closedAt: string | null;
    closedReason: string | null;
  };
}

export interface FixSummary {
  id: string;
  filePath: string;
}

export interface FixDetail extends FixSummary {
  diff: string;
  explanation: string;
  issueId: string;
}

export interface DispatchPentestResult {
  scanId: string;
  label: string;
  status: "queued";
  message: string;
}

export interface AgentLogEntry {
  id: string;
  createdAt: string;
  level: string;
  role: string;
  message: string;
  metadata: Record<string, unknown> | null;
  service: string | null;
  subagent: string | null;
}

export interface ListAgentLogsResult {
  issueId: string;
  totalLogs: number;
  returnedLogs: number;
  logs: AgentLogEntry[];
}

export interface SearchAgentLogsResult {
  issueId: string;
  query: string;
  totalMatches: number;
  totalLogs?: number;
  contextLines?: number;
  matches: Array<{
    matchIndex: number;
    entries: Array<AgentLogEntry & { isMatch: boolean }>;
  }>;
}

// ── HTTP helpers ─────────────────────────────────────────────────────

async function getAuthHeaders(): Promise<Record<string, string>> {
  const cfg = await config.get();

  const validToken = await ensureValidToken({
    accessToken: cfg.accessToken,
    refreshToken: cfg.refreshToken,
    pensarAPIKey: cfg.pensarAPIKey,
  });

  if (!validToken) {
    throw new Error(
      "Not authenticated. Run `pensar auth login` to connect to Pensar Console.",
    );
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${validToken.token}`,
  };

  if (validToken.type === "workos" && cfg.workspaceId) {
    headers["X-Workspace-Id"] = cfg.workspaceId;
  }

  return headers;
}

async function apiRequest<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const baseUrl = getPensarApiUrl();
  const headers = await getAuthHeaders();
  const url = `${baseUrl}${path}`;

  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }

  const response = await fetch(url, init);

  if (!response.ok) {
    const text = await response.text();
    let message: string;
    try {
      const err = JSON.parse(text) as { error?: string };
      message = err.error ?? text;
    } catch {
      message = text;
    }
    throw new Error(`API error (${response.status}): ${message}`);
  }

  return (await response.json()) as T;
}

// ── API functions ────────────────────────────────────────────────────

export async function listProjects(): Promise<ProjectSummary[]> {
  return apiRequest<ProjectSummary[]>("GET", "/projects");
}

export async function listScans(projectId: string): Promise<ScanSummary[]> {
  return apiRequest<ScanSummary[]>("GET", `/projects/${projectId}/pentests`);
}

export async function getScan(scanId: string): Promise<ScanDetail> {
  return apiRequest<ScanDetail>("GET", `/pentests/${scanId}`);
}

export async function dispatchPentest(
  projectId: string,
  opts?: { branch?: string; scanLevel?: "priority" | "full" },
): Promise<DispatchPentestResult> {
  return apiRequest<DispatchPentestResult>(
    "POST",
    `/projects/${projectId}/pentests`,
    opts,
  );
}

export async function listIssues(
  projectId: string,
  filters?: {
    scanId?: string;
    status?: string;
    severity?: string;
    branch?: string;
  },
): Promise<IssueSummary[]> {
  const params = new URLSearchParams();
  if (filters?.scanId) params.set("scanId", filters.scanId);
  if (filters?.status) params.set("status", filters.status);
  if (filters?.severity) params.set("severity", filters.severity);
  if (filters?.branch) params.set("branch", filters.branch);

  const qs = params.toString();
  const path = `/projects/${projectId}/issues${qs ? `?${qs}` : ""}`;
  return apiRequest<IssueSummary[]>("GET", path);
}

export async function getIssue(issueId: string): Promise<IssueDetail> {
  return apiRequest<IssueDetail>("GET", `/issues/${issueId}`);
}

export async function updateIssue(
  issueId: string,
  data: {
    status?: "open" | "closed" | "false-positive" | "in-review";
    userFlaggedFalsePositive?: boolean;
    userFlaggedFalsePositiveReason?: string;
    closedReason?: string;
    closedComments?: string;
  },
): Promise<UpdateIssueResult> {
  return apiRequest<UpdateIssueResult>("PATCH", `/issues/${issueId}`, data);
}

export async function listFixes(issueId: string): Promise<FixSummary[]> {
  return apiRequest<FixSummary[]>("GET", `/issues/${issueId}/fixes`);
}

export async function getFix(fixId: string): Promise<FixDetail> {
  return apiRequest<FixDetail>("GET", `/fixes/${fixId}`);
}

export async function listAgentLogs(
  issueId: string,
  opts?: {
    level?: "debug" | "info" | "warn" | "error";
    role?: "assistant" | "user" | "system" | "tool-call" | "tool-result";
    limit?: number;
  },
): Promise<ListAgentLogsResult> {
  const params = new URLSearchParams();
  if (opts?.level) params.set("level", opts.level);
  if (opts?.role) params.set("role", opts.role);
  if (opts?.limit) params.set("limit", String(opts.limit));

  const qs = params.toString();
  const path = `/issues/${issueId}/logs${qs ? `?${qs}` : ""}`;
  return apiRequest<ListAgentLogsResult>("GET", path);
}

export async function searchAgentLogs(
  issueId: string,
  query: string,
  opts?: {
    level?: "debug" | "info" | "warn" | "error";
    role?: "assistant" | "user" | "system" | "tool-call" | "tool-result";
    contextLines?: number;
  },
): Promise<SearchAgentLogsResult> {
  return apiRequest<SearchAgentLogsResult>(
    "POST",
    `/issues/${issueId}/logs/search`,
    { query, ...opts },
  );
}
