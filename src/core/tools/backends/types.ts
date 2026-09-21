/**
 * Host- and engine-neutral tool backend layer (design doc §3.2, Appendix B).
 *
 * A tool becomes `describe + validate + call backend`: it never touches
 * `fs`, `spawn`, `fetch`, a base64-echo write, or `ctx.sandbox`. `ToolBackends`
 * is injected; `LocalBackends` (this package) reproduces today's CLI/TUI
 * behaviour, and console layers `SandboxBackends` / `DurableBackends` /
 * `RedactingBackends` on top.
 *
 * Result types re-use exactly what today's tools return so the A2–A4 tool
 * migrations are mechanical.
 */

import type { CreateFileResult } from "../../agents/offSecAgent/tools/createFile";
import type { EmailAdapterResolver } from "../../agents/offSecAgent/tools/email/adapters";
import type { HttpRequestResult } from "../../agents/offSecAgent/tools/httpRequest";
import type {
  BrowserClickResult,
  BrowserConsoleResult,
  BrowserEvaluateResult,
  BrowserFillResult,
  BrowserNavigateResult,
  BrowserScreenshotResult,
} from "../../agents/offSecAgent/tools/playwrightMcp";
import type { SmsInbox } from "../../agents/offSecAgent/tools/smsInbox";

export type {
  ApplyPatchResult,
  FilePatchResult,
} from "../../agents/offSecAgent/tools/applyPatch";
export type { GlobResult } from "../../agents/offSecAgent/tools/glob";
export type { GrepResult } from "../../agents/offSecAgent/tools/grep";
export type { ListFilesResult } from "../../agents/offSecAgent/tools/listFiles";
export type {
  BrowserClickResult,
  BrowserConsoleResult,
  BrowserEvaluateResult,
  BrowserFillResult,
  BrowserNavigateResult,
  BrowserScreenshotResult,
} from "../../agents/offSecAgent/tools/playwrightMcp";
export type { ReadFileResult } from "../../agents/offSecAgent/tools/readFile";

import type { ApplyPatchResult } from "../../agents/offSecAgent/tools/applyPatch";
import type { GlobResult } from "../../agents/offSecAgent/tools/glob";
import type { GrepResult } from "../../agents/offSecAgent/tools/grep";
import type { ListFilesResult } from "../../agents/offSecAgent/tools/listFiles";
import type { ReadFileResult } from "../../agents/offSecAgent/tools/readFile";

/**
 * Whole-file write result. `create_file` returns this directly; `update_file`
 * reads, replaces, then writes and layers its own `replacements` count on top.
 */
export type WriteResult = CreateFileResult;

/** Arguments for {@link FsBackend.git}. Only `status`/`diff` are used locally. */
export interface GitArgs {
  /** Limit a `diff` to one path. */
  path?: string;
  /** `diff` the index instead of the working tree. */
  staged?: boolean;
  /** Sandbox-only source-materialisation ops (clone/snapshot/restore). */
  repoUrl?: string;
  ref?: string;
  message?: string;
}

/** Raw git output, matching the shared `runGit` seam plus the working dir. */
export interface GitResult {
  success: boolean;
  stdout: string;
  stderr: string;
  cwd: string;
}

export interface ReadOpts {
  startLine?: number;
  endLine?: number;
}

export interface ListOpts {
  recursive?: boolean;
}

export interface GrepQuery {
  pattern: string;
  directory?: string;
  flags?: string;
}

export interface GlobOpts {
  path?: string;
}

export type WriteMode = "create" | "overwrite";

/**
 * Whole-file, unformatted read (no line numbers, no truncation cap). `update_file`
 * needs the exact literal bytes for its search-and-replace match, which
 * {@link FsBackend.read}'s numbered/capped output can't provide.
 */
export interface RawReadResult {
  success: boolean;
  error: string;
  content: string;
  path: string;
}

export interface FsBackend {
  read(path: string, o?: ReadOpts): Promise<ReadFileResult>;
  /** Uncapped, unformatted read for callers that need exact file bytes (`update_file`). */
  readRaw(path: string): Promise<RawReadResult>;
  list(dir: string, o?: ListOpts): Promise<ListFilesResult>;
  grep(q: GrepQuery): Promise<GrepResult>;
  glob(pattern: string, o?: GlobOpts): Promise<GlobResult>;
  write(
    path: string,
    content: string,
    o: { mode: WriteMode },
  ): Promise<WriteResult>;
  delete(path: string): Promise<void>;
  applyPatch(diff: string): Promise<ApplyPatchResult>;
  git(
    op: "status" | "diff" | "clone" | "snapshot" | "restore",
    args?: GitArgs,
  ): Promise<GitResult>;
}

/**
 * One streamed command event. `stdout`/`stderr` carry a monotonic `seq` so a
 * surviving executor can reattach by offset (design §3.3); `end` carries the
 * final exit code and whether a timeout fired.
 */
export type CommandEvent =
  | { type: "start"; pid?: number }
  | { type: "stdout"; seq: number; bytes: string }
  | { type: "stderr"; seq: number; bytes: string }
  | { type: "end"; exitCode: number; timedOut: boolean };

export interface RunOpts {
  /** Seconds. Millisecond-style values are normalised down. */
  timeoutSeconds?: number;
  /** Extra env for this command only (isolated via `env … bash -lc`). */
  envVars?: Record<string, string>;
  abortSignal?: AbortSignal;
}

export interface CommandBackend {
  run(cmd: string, o?: RunOpts): AsyncIterable<CommandEvent>;
}

export type HttpMethod =
  | "GET"
  | "POST"
  | "PUT"
  | "DELETE"
  | "PATCH"
  | "OPTIONS"
  | "HEAD";

export interface HttpRequest {
  url: string;
  method?: HttpMethod;
  headers?: Record<string, string>;
  body?: string;
  followRedirects?: boolean;
  /** `get_page` folds into `http_request` here (design §5.4, Appendix L). */
  extract?: "readability";
}

export interface HttpOpts {
  /** Milliseconds; no timeout when omitted. */
  timeoutMs?: number;
  abortSignal?: AbortSignal;
}

/** Matches `http_request`'s result, plus the readability page title. */
export interface HttpResponse extends HttpRequestResult {
  title?: string;
}

export interface HttpBackend {
  request(req: HttpRequest, o?: HttpOpts): Promise<HttpResponse>;
}

export interface BrowserSnapshotResult {
  success: boolean;
  snapshot?: string;
  error?: string;
}

export interface BrowserCookiesResult {
  success: boolean;
  cookies?: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    httpOnly: boolean;
    secure: boolean;
  }>;
  cookieHeader?: string;
  error?: string;
}

/** Today's `sandboxPlaywright` surface (design §3.2). */
export interface BrowserBackend {
  navigate(url: string): Promise<BrowserNavigateResult>;
  snapshot(): Promise<BrowserSnapshotResult>;
  screenshot(o: { filename: string }): Promise<BrowserScreenshotResult>;
  click(o: { element: string; ref?: string }): Promise<BrowserClickResult>;
  fill(o: {
    element: string;
    ref?: string;
    value: string;
  }): Promise<BrowserFillResult>;
  evaluate(o: { script: string }): Promise<BrowserEvaluateResult>;
  console(): Promise<BrowserConsoleResult>;
  getCookies(o?: { urls?: string[] }): Promise<BrowserCookiesResult>;
}

/** The #1051 inbox seams, relocated (design §3.2). */
export interface InboxBackend {
  email: EmailAdapterResolver;
  sms: SmsInbox;
}

export interface ToolBackends {
  fs: FsBackend;
  command: CommandBackend;
  http: HttpBackend;
  browser: BrowserBackend;
  inbox: InboxBackend;
}
