/**
 * `LocalBackends` — the apex (CLI/TUI) implementation of {@link ToolBackends}.
 *
 * Reproduces today's local behaviour byte-for-byte: filesystem via `node:fs`,
 * `command` via the shared `commandShell`, `http` via `targetFetch` (plus
 * the `get_page` readability extract), `browser` via the local Playwright-MCP
 * toolset, and `inbox` via the #1051 seams. Every call consults a
 * {@link ToolPolicy} first; the default composes engagement scope and the
 * destructive-action block.
 */

import { join } from "node:path";
import type { ToolCallOptions } from "ai";
import { applyPatchImpl } from "../../agents/offSecAgent/tools/applyPatchImpl";
import {
  deleteWorkspaceFile,
  readWorkspaceFile,
  resolveFilePath,
  writeWorkspaceFile,
} from "../../agents/offSecAgent/tools/fileWorkspace";
import { runGit } from "../../agents/offSecAgent/tools/gitStatus";
import { globImpl } from "../../agents/offSecAgent/tools/globImpl";
import { grepImpl } from "../../agents/offSecAgent/tools/grepImpl";
import { listFilesImpl } from "../../agents/offSecAgent/tools/listFilesImpl";
import { createBrowserTools } from "../../agents/offSecAgent/tools/playwrightMcp";
import { readFileImpl } from "../../agents/offSecAgent/tools/readFileImpl";
import { resolverSessionFromCtx } from "../../agents/offSecAgent/tools/scopeGuard";
import { HttpSmsInbox } from "../../agents/offSecAgent/tools/smsInbox";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import { resolveEffectiveHeaders, targetFetch } from "../../http/targetHeaders";
import type { HeaderRecord } from "../../http/types";
import {
  CAPS,
  normalizeExecuteCommandTimeout,
  redactSecretValues,
} from "./helpers";
import {
  type BackendName,
  defaultPolicy,
  type ToolPolicy,
  ToolPolicyDeniedError,
} from "./policy";
import type {
  ApplyPatchResult,
  BrowserClickResult,
  BrowserConsoleResult,
  BrowserCookiesResult,
  BrowserEvaluateResult,
  BrowserFillResult,
  BrowserNavigateResult,
  BrowserScreenshotResult,
  BrowserSnapshotResult,
  CommandEvent,
  DeleteOpts,
  GitArgs,
  GitResult,
  GlobOpts,
  GlobResult,
  GrepQuery,
  GrepResult,
  HttpOpts,
  HttpRequest,
  HttpResponse,
  ListFilesResult,
  ListOpts,
  RawReadResult,
  ReadFileResult,
  ReadOpts,
  RunOpts,
  ToolBackends,
  WriteOpts,
  WriteResult,
} from "./types";

// get_page readability baselines
const GETPAGE_USER_AGENT =
  "Mozilla/5.0 (compatible; PensarBot/1.0; +https://pensar.dev)";
const BASELINE_FALLBACK_HEADERS: HeaderRecord = {
  Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.5",
};

const BROWSER_TOOL_OPTIONS = {
  toolCallId: "backend",
  messages: [],
} as ToolCallOptions;

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function mergeBaselineHeaders(resolved: HeaderRecord): HeaderRecord {
  const present = new Set(Object.keys(resolved).map((k) => k.toLowerCase()));
  const out: HeaderRecord = { ...resolved };
  out["User-Agent"] = GETPAGE_USER_AGENT;
  for (const [name, value] of Object.entries(BASELINE_FALLBACK_HEADERS)) {
    if (!present.has(name.toLowerCase())) out[name] = value;
  }
  return out;
}

function extractTitle(html: string): string | undefined {
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return titleMatch?.[1]?.trim();
}

function extractTextContent(html: string): string {
  let text = html;
  text = text.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "");
  text = text.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "");
  text = text.replace(/<noscript[^>]*>[\s\S]*?<\/noscript>/gi, "");
  text = text.replace(/<!--[\s\S]*?-->/g, "");
  text = text.replace(/<[^>]+>/g, " ");
  text = text
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'");
  text = text.replace(/\s+/g, " ").trim();
  const lines = text
    .split(/[.\n]/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  return lines.join("\n");
}

/**
 * Build the local backends for `ctx`. `policy` is consulted before every call;
 * it defaults to {@link defaultPolicy}.
 */
export function LocalBackends(
  ctx: ToolContext,
  policy: ToolPolicy = defaultPolicy,
): ToolBackends {
  async function checkPolicy(
    backend: BackendName,
    op: string,
    args: unknown,
  ): Promise<void> {
    const decision = await policy.beforeCall({ backend, op, args, ctx });
    if (!decision.allow) {
      throw new ToolPolicyDeniedError(backend, op, decision.reason);
    }
  }

  const fs: ToolBackends["fs"] = {
    async read(path: string, o?: ReadOpts): Promise<ReadFileResult> {
      await checkPolicy("fs", "read", { path });
      return readFileImpl(ctx, path, o);
    },

    async readRaw(path: string): Promise<RawReadResult> {
      await checkPolicy("fs", "readRaw", { path });
      let resolved = path;
      try {
        resolved = await resolveFilePath(ctx, path);
        const content = await readWorkspaceFile(ctx, resolved);
        return { success: true, error: "", content, path: resolved };
      } catch (err: unknown) {
        return {
          success: false,
          error: errMessage(err),
          content: "",
          path: resolved,
        };
      }
    },

    async list(dir: string, o?: ListOpts): Promise<ListFilesResult> {
      await checkPolicy("fs", "list", { dir });
      return listFilesImpl(ctx, dir, o);
    },

    async grep(q: GrepQuery): Promise<GrepResult> {
      await checkPolicy("fs", "grep", {
        pattern: q.pattern,
        directory: q.directory,
        flags: q.flags,
      });
      return grepImpl(ctx, q);
    },

    async glob(pattern: string, o?: GlobOpts): Promise<GlobResult> {
      await checkPolicy("fs", "glob", { pattern, path: o?.path });
      return globImpl(ctx, pattern, o);
    },

    async write(
      path: string,
      content: string,
      o: WriteOpts,
    ): Promise<WriteResult> {
      await checkPolicy("fs", "write", { path, mode: o.mode });
      let resolved = path;
      try {
        resolved = await resolveFilePath(ctx, path);
        // `expected` layers optimistic concurrency on `mode`: an explicit value
        // (update_file's last-read content) wins; otherwise a create is an
        // exclusive `null` and an overwrite skips the check.
        const expected =
          "expected" in o ? o.expected : o.mode === "create" ? null : undefined;
        await writeWorkspaceFile(ctx, resolved, content, { expected });
        return { success: true, error: "", path: resolved };
      } catch (err: unknown) {
        return { success: false, error: errMessage(err), path: resolved };
      }
    },

    async delete(path: string, o?: DeleteOpts): Promise<void> {
      await checkPolicy("fs", "delete", { path });
      const resolved = await resolveFilePath(ctx, path, {
        confineToCwd: o?.confineToCwd ?? true,
        followFinal: false,
      });
      await deleteWorkspaceFile(
        ctx,
        resolved,
        o?.expected !== undefined ? { expected: o.expected } : undefined,
      );
    },

    async applyPatch(diff: string): Promise<ApplyPatchResult> {
      await checkPolicy("fs", "applyPatch", {});
      return applyPatchImpl(ctx, diff);
    },

    async git(
      op: "status" | "diff" | "clone" | "snapshot" | "restore",
      args?: GitArgs,
    ): Promise<GitResult> {
      await checkPolicy("fs", "git", { op, args });
      if (op === "status") {
        const r = await runGit(ctx, ["status", "--porcelain"]);
        return { ...r, cwd: ctx.agentCwd };
      }
      if (op === "diff") {
        const gitArgs = ["diff"];
        if (args?.staged) gitArgs.push("--cached");
        if (args?.path) gitArgs.push("--", args.path);
        const r = await runGit(ctx, gitArgs);
        return { ...r, cwd: ctx.agentCwd };
      }
      throw new Error(
        `git ${op} is not supported by LocalBackends (sandbox-only)`,
      );
    },
  };

  const command: ToolBackends["command"] = {
    run(cmd: string, o?: RunOpts): AsyncIterable<CommandEvent> {
      return runCommand(ctx, policy, cmd, o);
    },
  };

  const http: ToolBackends["http"] = {
    async request(req: HttpRequest, o?: HttpOpts): Promise<HttpResponse> {
      // The destructive guard must see session/credential headers too, since
      // targetFetch merges them in before sending.
      await checkPolicy("http", "request", {
        method: req.method ?? "GET",
        url: req.url,
        body: req.body,
        headers: resolveEffectiveHeaders(
          resolverSessionFromCtx(ctx),
          req.url,
          req.headers,
        ),
        extract: req.extract,
      });
      if (req.extract === "readability") {
        return fetchReadable(ctx, req.url, o);
      }
      return fetchStandard(ctx, req, o);
    },
  };

  let playwrightTools: ReturnType<typeof createBrowserTools> | null = null;
  function tools(): ReturnType<typeof createBrowserTools> {
    if (!playwrightTools) {
      playwrightTools = createBrowserTools(
        ctx.target ?? "",
        join(ctx.session.rootPath, "evidence"),
        "operator",
        undefined,
        ctx.abortSignal,
        undefined,
        undefined,
        undefined,
        ctx.browserSession,
      );
    }
    return playwrightTools;
  }
  async function browserExec<T>(
    op: string,
    tool: { execute?: unknown },
    input: unknown,
  ): Promise<T> {
    await checkPolicy("browser", op, input);
    const fn = tool.execute as
      | ((i: unknown, options: ToolCallOptions) => Promise<unknown>)
      | undefined;
    if (!fn) throw new Error(`browser tool ${op} has no execute`);
    return (await fn(input, BROWSER_TOOL_OPTIONS)) as T;
  }

  const browser: ToolBackends["browser"] = {
    navigate: (url) =>
      browserExec<BrowserNavigateResult>("navigate", tools().browser_navigate, {
        url,
      }),
    snapshot: () =>
      browserExec<BrowserSnapshotResult>(
        "snapshot",
        tools().browser_snapshot,
        {},
      ),
    screenshot: (o) =>
      browserExec<BrowserScreenshotResult>(
        "screenshot",
        tools().browser_screenshot,
        o,
      ),
    click: (o) =>
      browserExec<BrowserClickResult>("click", tools().browser_click, o),
    fill: (o) =>
      browserExec<BrowserFillResult>("fill", tools().browser_fill, o),
    evaluate: (o) =>
      browserExec<BrowserEvaluateResult>(
        "evaluate",
        tools().browser_evaluate,
        o,
      ),
    console: () =>
      browserExec<BrowserConsoleResult>("console", tools().browser_console, {}),
    getCookies: (o) =>
      browserExec<BrowserCookiesResult>(
        "getCookies",
        tools().browser_get_cookies,
        o ?? {},
      ),
  };

  const inbox: ToolBackends["inbox"] = {
    email: ctx.emailAdapterFor ?? (() => null),
    sms: ctx.smsInbox ?? new HttpSmsInbox(),
  };

  return { fs, command, http, browser, inbox };
}

// ---------------------------------------------------------------------------
// command.run — commandShell streamed as CommandEvents
// ---------------------------------------------------------------------------

async function* runCommand(
  ctx: ToolContext,
  policy: ToolPolicy,
  cmd: string,
  o?: RunOpts,
): AsyncGenerator<CommandEvent> {
  const decision = await policy.beforeCall({
    backend: "command",
    op: "run",
    args: { command: cmd },
    ctx,
  });
  if (!decision.allow) {
    throw new ToolPolicyDeniedError("command", "run", decision.reason);
  }

  const shell = ctx.commandShell;
  if (!shell) {
    yield { type: "start" };
    yield {
      type: "stderr",
      seq: 0,
      bytes: "No shell available (LocalBackends requires a commandShell)",
    };
    yield { type: "end", exitCode: 1, timedOut: false };
    return;
  }

  yield { type: "start" };

  const queue: CommandEvent[] = [];
  let seq = 0;
  let done = false;
  let notify: (() => void) | null = null;
  const wake = () => {
    if (notify) {
      const f = notify;
      notify = null;
      f();
    }
  };

  const normalized = normalizeExecuteCommandTimeout(o?.timeoutSeconds);

  // `onData` streams the shell's best-effort live view of stdout as the command
  // runs; `res.stdout` (below) is the authoritative post-cutover recapture of
  // the same file, which can include trailing bytes the live poll missed. Track
  // how much was already streamed so the remainder — not a duplicate of the
  // whole thing — closes the gap; a consumer that concatenates every `stdout`
  // event ends up with the authoritative text. The per-command shell owns env
  // injection and the clean (no-profile) bash invocation, so the raw command is
  // handed straight to it.
  let rawStreamedLen = 0;
  const execPromise = shell
    .execute(cmd, {
      timeoutSeconds: normalized,
      env: o?.envVars,
      onData: (chunk: string) => {
        rawStreamedLen += chunk.length;
        queue.push({
          type: "stdout",
          seq: seq++,
          bytes: redactSecretValues(chunk, ctx.secretValues),
        });
        wake();
      },
      abortSignal: o?.abortSignal,
    })
    .then((res) => {
      const remainder =
        rawStreamedLen === 0
          ? res.stdout
          : res.stdout.length > rawStreamedLen
            ? res.stdout.slice(rawStreamedLen)
            : "";
      if (remainder) {
        queue.push({
          type: "stdout",
          seq: seq++,
          bytes: redactSecretValues(remainder, ctx.secretValues),
        });
      }
      const stderr = redactSecretValues(res.stderr, ctx.secretValues);
      if (stderr) {
        queue.push({ type: "stderr", seq: seq++, bytes: stderr });
      }
      queue.push({
        type: "end",
        exitCode: res.exitCode,
        timedOut: res.exitCode === 124,
      });
      done = true;
      wake();
    })
    .catch((err) => {
      // Wake the parked loop before re-throwing so `await execPromise` below
      // surfaces the failure instead of the generator blocking forever.
      done = true;
      wake();
      throw err;
    });

  while (true) {
    while (queue.length > 0) {
      yield queue.shift() as CommandEvent;
    }
    if (done) break;
    await new Promise<void>((r) => {
      notify = r;
    });
  }
  await execPromise;
}

// ---------------------------------------------------------------------------
// http.request
// ---------------------------------------------------------------------------

async function fetchStandard(
  ctx: ToolContext,
  req: HttpRequest,
  o?: HttpOpts,
): Promise<HttpResponse> {
  const method = req.method ?? "GET";
  const headers = req.headers ?? {};
  const timeout = o?.timeoutMs;
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  try {
    const timeoutController = new AbortController();
    if (timeout !== undefined) {
      timeoutId = setTimeout(() => timeoutController.abort(), timeout);
    }
    const combinedSignal = o?.abortSignal
      ? AbortSignal.any([o.abortSignal, timeoutController.signal])
      : timeoutController.signal;

    const response = await targetFetch(resolverSessionFromCtx(ctx), req.url, {
      method,
      headers,
      body: req.body || undefined,
      redirect: req.followRedirects ? "follow" : "manual",
      signal: combinedSignal,
    });
    clearTimeout(timeoutId);

    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });
    let responseBody = "";
    try {
      responseBody = await response.text();
    } catch {
      responseBody = "(unable to read response body)";
    }
    return {
      success: true,
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: responseBody,
      url: response.url,
      redirected: response.redirected,
    };
  } catch (error: unknown) {
    if (timeoutId) clearTimeout(timeoutId);
    const isAbort = error instanceof Error && error.name === "AbortError";
    const errorMsg = isAbort
      ? o?.abortSignal?.aborted
        ? "Request aborted by user"
        : `Request timeout after ${timeout}ms`
      : errMessage(error);
    return {
      success: false,
      error: errorMsg,
      url: req.url,
      method,
      status: 0,
      statusText: "",
      headers: {},
      body: "",
      redirected: false,
    };
  }
}

async function fetchReadable(
  ctx: ToolContext,
  url: string,
  o?: HttpOpts,
): Promise<HttpResponse> {
  const controller = new AbortController();
  const timeoutId = setTimeout(
    () => controller.abort(),
    CAPS.READABILITY_TIMEOUT_MS,
  );
  const combinedSignal = o?.abortSignal
    ? AbortSignal.any([o.abortSignal, controller.signal])
    : controller.signal;
  try {
    const headers = mergeBaselineHeaders(
      resolveEffectiveHeaders(resolverSessionFromCtx(ctx), url),
    );
    const response = await fetch(url, {
      method: "GET",
      headers,
      signal: combinedSignal,
      redirect: "follow",
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        success: false,
        url,
        status: response.status,
        statusText: response.statusText,
        headers: {},
        body: "",
        redirected: false,
        error: `Failed to fetch page: ${response.status} ${response.statusText}`,
      };
    }

    const contentType = response.headers.get("content-type") || "";
    if (
      !contentType.includes("text/html") &&
      !contentType.includes("text/plain") &&
      !contentType.includes("application/xhtml")
    ) {
      return {
        success: false,
        url,
        status: response.status,
        statusText: response.statusText,
        headers: {},
        body: "",
        redirected: response.redirected,
        error: `Unsupported content type: ${contentType}. This tool only supports HTML and text pages.`,
      };
    }

    const html = await response.text();
    const title = extractTitle(html);
    let content = extractTextContent(html);
    if (content.length > CAPS.READABILITY_MAX_CHARS) {
      content = `${content.substring(0, CAPS.READABILITY_MAX_CHARS)}\n\n... (content truncated — page exceeded maximum length)`;
    }
    return {
      success: true,
      url,
      title,
      status: response.status,
      statusText: response.statusText,
      headers: {},
      body: content,
      redirected: response.redirected,
    };
  } catch (error: unknown) {
    clearTimeout(timeoutId);
    const isAbort = error instanceof Error && error.name === "AbortError";
    const errorMsg = isAbort
      ? o?.abortSignal?.aborted
        ? "Request aborted by user"
        : `Request timeout after ${CAPS.READABILITY_TIMEOUT_MS / 1000}s`
      : `Failed to fetch page: ${errMessage(error)}`;
    return {
      success: false,
      url,
      status: 0,
      statusText: "",
      headers: {},
      body: "",
      redirected: false,
      error: errorMsg,
    };
  }
}
