/**
 * Tool backend layer (design §3.2, Appendix B, Appendix M).
 *
 * `ToolBackends` is the host- and engine-neutral surface every tool composes
 * over; `LocalBackends` is the apex CLI/TUI implementation; `defaultPolicy` is
 * the deterministic scope + destructive-action gate consulted before each call.
 * Shared helpers (`resolveContained`, redaction, spill, timeout, base64 sandbox
 * writes) live here once so A2–A4 can delete their per-tool copies.
 */

export {
  CAPS,
  deleteViaSandbox,
  maybeSaveFullOutput,
  normalizeExecuteCommandTimeout,
  readViaSandbox,
  redactSecretValues,
  resolveContained,
  writeViaSandbox,
} from "./helpers";
export { LocalBackends } from "./local";
export {
  type BackendName,
  defaultPolicy,
  type PolicyDecision,
  type ToolPolicy,
  type ToolPolicyCall,
  ToolPolicyDeniedError,
} from "./policy";
export { resolveBackends } from "./resolve";
export type {
  ApplyPatchResult,
  BrowserBackend,
  BrowserClickResult,
  BrowserConsoleResult,
  BrowserCookiesResult,
  BrowserEvaluateResult,
  BrowserFillResult,
  BrowserNavigateResult,
  BrowserScreenshotResult,
  BrowserSnapshotResult,
  CommandBackend,
  CommandEvent,
  FilePatchResult,
  FsBackend,
  GitArgs,
  GitResult,
  GlobOpts,
  GlobResult,
  GrepQuery,
  GrepResult,
  HttpBackend,
  HttpMethod,
  HttpOpts,
  HttpRequest,
  HttpResponse,
  InboxBackend,
  ListFilesResult,
  ListOpts,
  RawReadResult,
  ReadFileResult,
  ReadOpts,
  RunOpts,
  ToolBackends,
  WriteMode,
  WriteResult,
} from "./types";
