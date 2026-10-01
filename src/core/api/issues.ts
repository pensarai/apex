/**
 * REST API client for the Pensar Issues API.
 *
 * Wraps the /{proxy+} endpoints exposed by the console's issues-api Lambda.
 * Auth is handled via Bearer token (WorkOS JWT) or API key, with an
 * X-Workspace-Id header for JWT auth.
 */

import { apiRequest } from "./apiClient";

// ── Types ────────────────────────────────────────────────────────────

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
  workspaceId: string;
  workspaceName: string;
  errorMessage?: string;
  issuesFound: number;
  reportReady: boolean;
}

/**
 * Close dispositions the API accepts. Mirrors the server's public vocabulary;
 * `other` is deliberately absent — the server rejects it.
 */
export const CLOSED_DISPOSITIONS = [
  "resolved",
  "wont-fix",
  "out-of-scope",
  "risk-accepted",
] as const;

export type ClosedDisposition = (typeof CLOSED_DISPOSITIONS)[number];

export interface IssueSummary {
  id: string;
  /** Human-facing label, e.g. `VULN-000123`. Null for issues created before labels existed. */
  issueLabel: string | null;
  title: string;
  severity: string;
  status: string;
  location: string;
  /** Console deep link for the issue. */
  url: string;
}

export interface IssueDetail extends IssueSummary {
  description?: string;
  lineRange?: string;
  cwe?: string;
  branch?: string;
  endpoint?: string;
  poc?: string;
  workspaceId: string;
  workspaceName: string;
  createdAt: string;
  /** Close metadata. Absent when talking to a console that predates it. */
  closedAt?: string | null;
  closedMethod?: string | null;
  closedReason?: string | null;
  closedComments?: string | null;
  closedDisposition?: ClosedDisposition | null;
}

/** Who wrote a comment. Null when the author's user record is gone. */
export interface CommentAuthor {
  id: string;
  name: string | null;
  email: string;
  type: "user";
}

export interface IssueCommentSummary {
  id: string;
  issueId: string;
  /** Comment text as written; `@handle` mentions are left in place. */
  body: string;
  author: CommentAuthor | null;
  createdAt: string;
  /** Null if the comment has never been edited. */
  editedAt: string | null;
  /** Console deep link to the comment. */
  url: string;
}

export interface IssueCommentPage {
  comments: IssueCommentSummary[];
  pagination: {
    page: number;
    pageSize: number;
    totalRows: number;
    totalPages: number;
  };
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
    closedMethod?: string | null;
    closedComments?: string | null;
    closedDisposition?: ClosedDisposition | null;
  };
}

export interface RetestIssueResult {
  issueId: string;
  sessionId: string;
  status: "queued";
  message: string;
}

export interface PullRequestSummary {
  id: number;
  url: string;
  status: string;
  createMethod: string;
  createdAt: string;
}

export interface LinkPullRequestResult {
  success: boolean;
  created: boolean;
  pullRequest: PullRequestSummary;
  issue: {
    id: string;
    issueLabel: string | null;
    name: string | null;
    pullRequest: string;
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

/**
 * A pentest "target" is a single attack-surface endpoint exercised during a
 * pentest (a `scan_endpoints` row on the backend). Pentest execution logs are
 * persisted against the target rather than against any issue it produced, so
 * targets are the entry point for querying those logs.
 */
export interface PentestTargetSummary {
  id: string;
  url: string | null;
  applicationId: string;
  applicationName: string;
  status: string;
  attempt: number;
  startedAt?: string;
  completedAt?: string;
  error: string | null;
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

export interface ListTargetLogsResult {
  targetId: string;
  totalLogs: number;
  returnedLogs: number;
  logs: AgentLogEntry[];
}

export interface SearchTargetLogsResult {
  targetId: string;
  query: string;
  totalMatches: number;
  totalLogs?: number;
  contextLines?: number;
  matches: Array<{
    matchIndex: number;
    entries: Array<AgentLogEntry & { isMatch: boolean }>;
  }>;
}

// ── API functions ────────────────────────────────────────────────────

export async function listScans(): Promise<ScanSummary[]> {
  return apiRequest<ScanSummary[]>("GET", "/pentests");
}

export async function getScan(scanId: string): Promise<ScanDetail> {
  return apiRequest<ScanDetail>("GET", `/pentests/${scanId}`);
}

export async function listPentestTargets(
  pentestId: string,
): Promise<PentestTargetSummary[]> {
  return apiRequest<PentestTargetSummary[]>(
    "GET",
    `/pentests/${pentestId}/targets`,
  );
}

export async function dispatchPentest(opts?: {
  branch?: string;
  scanLevel?: "priority" | "full";
}): Promise<DispatchPentestResult> {
  return apiRequest<DispatchPentestResult>("POST", "/pentests", opts);
}

export async function listIssues(filters?: {
  scanId?: string;
  status?: string;
  severity?: string;
  branch?: string;
}): Promise<IssueSummary[]> {
  const params = new URLSearchParams();
  if (filters?.scanId) params.set("scanId", filters.scanId);
  if (filters?.status) params.set("status", filters.status);
  if (filters?.severity) params.set("severity", filters.severity);
  if (filters?.branch) params.set("branch", filters.branch);

  const qs = params.toString();
  const path = `/issues${qs ? `?${qs}` : ""}`;
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
    closedDisposition?: ClosedDisposition;
  },
): Promise<UpdateIssueResult> {
  return apiRequest<UpdateIssueResult>("PATCH", `/issues/${issueId}`, data);
}

/**
 * The review thread on an issue, oldest first. Posting requires a user
 * credential — a workspace API key has no author to attribute a comment to.
 */
export async function listIssueComments(
  issueId: string,
  options?: { page?: number; pageSize?: number },
): Promise<IssueCommentPage> {
  const params = new URLSearchParams();
  if (options?.page) params.set("page", String(options.page));
  if (options?.pageSize) params.set("pageSize", String(options.pageSize));

  const qs = params.toString();
  return apiRequest<IssueCommentPage>(
    "GET",
    `/issues/${issueId}/comments${qs ? `?${qs}` : ""}`,
  );
}

export async function createIssueComment(
  issueId: string,
  body: string,
): Promise<IssueCommentSummary> {
  return apiRequest<IssueCommentSummary>(
    "POST",
    `/issues/${issueId}/comments`,
    { body },
  );
}

export async function retestIssue(issueId: string): Promise<RetestIssueResult> {
  return apiRequest<RetestIssueResult>("POST", `/issues/${issueId}/retest`);
}

/**
 * Link an externally opened pull request to an issue so Pensar tracks its
 * status and closes the issue when the PR merges. `issueId` accepts a UUID
 * or a `VULN-XXXXXX` label. Idempotent per (issue, url).
 */
export async function linkPullRequest(
  issueId: string,
  url: string,
): Promise<LinkPullRequestResult> {
  return apiRequest<LinkPullRequestResult>(
    "POST",
    `/issues/${issueId}/pull-requests`,
    { url },
  );
}

export async function listIssuePullRequests(
  issueId: string,
): Promise<PullRequestSummary[]> {
  return apiRequest<PullRequestSummary[]>(
    "GET",
    `/issues/${issueId}/pull-requests`,
  );
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

export async function listTargetLogs(
  targetId: string,
  opts?: {
    level?: "debug" | "info" | "warn" | "error";
    role?: "assistant" | "user" | "system" | "tool-call" | "tool-result";
    limit?: number;
  },
): Promise<ListTargetLogsResult> {
  const params = new URLSearchParams();
  if (opts?.level) params.set("level", opts.level);
  if (opts?.role) params.set("role", opts.role);
  if (opts?.limit) params.set("limit", String(opts.limit));

  const qs = params.toString();
  const path = `/targets/${targetId}/logs${qs ? `?${qs}` : ""}`;
  return apiRequest<ListTargetLogsResult>("GET", path);
}

export async function searchTargetLogs(
  targetId: string,
  query: string,
  opts?: {
    level?: "debug" | "info" | "warn" | "error";
    role?: "assistant" | "user" | "system" | "tool-call" | "tool-result";
    contextLines?: number;
  },
): Promise<SearchTargetLogsResult> {
  return apiRequest<SearchTargetLogsResult>(
    "POST",
    `/targets/${targetId}/logs/search`,
    { query, ...opts },
  );
}
