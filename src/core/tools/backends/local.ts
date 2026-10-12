import {
  PerCommandShell,
  readSandboxAgentEnv,
} from "../../agents/offSecAgent/tools/perCommandShell";
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
import { applyPatchImpl } from "../../agents/offSecAgent/tools/applyPatchImpl";
import { resolveBrowserHeaderPolicy } from "../../agents/offSecAgent/tools/browserHeaderRouting";
import {
  deleteWorkspaceFile,
  readWorkspaceFile,
  resolveFilePath,
  writeWorkspaceFile,
} from "../../agents/offSecAgent/tools/fileWorkspace";
import { globImpl } from "../../agents/offSecAgent/tools/globImpl";
import { grepImpl } from "../../agents/offSecAgent/tools/grepImpl";
import { listFilesImpl } from "../../agents/offSecAgent/tools/listFilesImpl";
import { createPlaywrightBrowserBackend } from "../../agents/offSecAgent/tools/playwrightMcp";
import { readFileImpl } from "../../agents/offSecAgent/tools/readFileImpl";
import { SandboxBrowserBackend } from "../../agents/offSecAgent/tools/sandboxPlaywright";
import { resolverSessionFromCtx } from "../../agents/offSecAgent/tools/scopeGuard";
import { HttpSmsInbox } from "../../agents/offSecAgent/tools/smsInbox";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import {
  fetchWithScopedRedirects,
  TargetRedirectError,
} from "../../http/redirects";
import { resolveEffectiveHeaders, targetFetch } from "../../http/targetHeaders";
import type { HeaderRecord } from "../../http/types";
import { collectCommand } from "./collectCommand";
import {
  CAPS,
  normalizeExecuteCommandTimeout,
  redactSecretValues,
} from "./helpers";
import { readHttpBodyCapped, requestSandboxHttp } from "./httpTransport";
import {
  type BackendName,
  defaultPolicy,
  type ToolPolicy,
  ToolPolicyDeniedError,
} from "./policy";
import type {
  ApplyPatchResult,
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
  fileOptions: { maxTextFileBytes?: number } = {},
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
        const content = await readWorkspaceFile(
          ctx,
          resolved,
          fileOptions.maxTextFileBytes,
        );
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
        resolved = await resolveFilePath(ctx, path, {
          timeoutSeconds: o.timeoutSeconds,
        });
        // `expected` layers optimistic concurrency on `mode`: an explicit value
        // (update_file's last-read content) wins; otherwise a create is an
        // exclusive `null` and an overwrite skips the check.
        const expected =
          "expected" in o ? o.expected : o.mode === "create" ? null : undefined;
        await writeWorkspaceFile(ctx, resolved, content, {
          expected,
          timeoutSeconds: o.timeoutSeconds,
          maxBytes: fileOptions.maxTextFileBytes,
          permissions: o.permissions,
        });
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
      if (op === "status" || op === "diff") {
        const gitArgs = op === "status" ? ["status", "--porcelain"] : ["diff"];
        if (op === "diff" && args?.staged) gitArgs.push("--cached");
        if (op === "diff" && args?.path) gitArgs.push("--", args.path);
        const cmd = `git ${gitArgs.map((arg) => `'${arg.replace(/'/g, `'\\''`)}'`).join(" ")}`;
        const result = await collectCommand(
          runCommand(ctx, policy, cmd, {
            timeoutSeconds: 30,
            abortSignal: ctx.abortSignal,
          }),
        );
        return {
          success: result.exitCode === 0,
          stdout: result.stdout,
          stderr: result.stderr,
          stdoutTruncated: result.stdoutTruncated === true,
          cwd: ctx.agentCwd,
        };
      }
      throw new Error(
        `git ${op} is not supported by LocalBackends (sandbox-only)`,
      );
    },
  };

  const command: ToolBackends["command"] = {
    platform: (
      ctx.sandbox
        ? ctx.sandbox.type === "windows"
        : process.platform === "win32"
    )
      ? "windows"
      : "posix",
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

  let localBrowser:
    | ReturnType<typeof createPlaywrightBrowserBackend>
    | undefined;
  function browserTransport() {
    localBrowser ??= ctx.sandbox
      ? SandboxBrowserBackend(ctx, policy)
      : createPlaywrightBrowserBackend(
          join(ctx.session.rootPath, "evidence"),
          undefined,
          ctx.abortSignal,
          undefined,
          undefined,
          undefined,
          ctx.browserSession,
          resolveBrowserHeaderPolicy(resolverSessionFromCtx(ctx), ctx.target),
        );
    return localBrowser;
  }
  async function browserExec<T>(
    op: string,
    input: unknown,
    execute: () => Promise<T>,
  ): Promise<T> {
    if (!ctx.sandbox) await checkPolicy("browser", op, input);
    return execute();
  }
  const browser: ToolBackends["browser"] = {
    navigate: (url) =>
      browserExec("navigate", { url }, () => browserTransport().navigate(url)),
    snapshot: () =>
      browserExec("snapshot", {}, () => browserTransport().snapshot()),
    screenshot: (o) =>
      browserExec("screenshot", o, () => browserTransport().screenshot(o)),
    click: (o) => browserExec("click", o, () => browserTransport().click(o)),
    fill: (o) => browserExec("fill", o, () => browserTransport().fill(o)),
    evaluate: (o) =>
      browserExec("evaluate", o, () => browserTransport().evaluate(o)),
    console: () =>
      browserExec("console", {}, () => browserTransport().console()),
    getCookies: (o) =>
      browserExec("getCookies", o ?? {}, () =>
        browserTransport().getCookies(o),
      ),
  };

  const inbox: ToolBackends["inbox"] = {
    email: ctx.emailAdapterFor ?? (() => null),
    sms: ctx.smsInbox ?? new HttpSmsInbox(),
  };

  return {
    fs,
    command,
    http,
    browser,
    inbox,
    ...(ctx.sandbox ? { sandboxed: true } : {}),
  };
}

// ---------------------------------------------------------------------------
// command.run — commandShell streamed as CommandEvents
// ---------------------------------------------------------------------------

export function runLocalProgram(
  ctx: ToolContext,
  commandText: string,
  executable: string,
  args: readonly string[],
  options?: RunOpts,
): AsyncIterable<CommandEvent> {
  return runCommand(ctx, defaultPolicy, commandText, options, {
    executable,
    args,
  });
}

async function* runCommand(
  ctx: ToolContext,
  policy: ToolPolicy,
  cmd: string,
  o?: RunOpts,
  program?: { executable: string; args: readonly string[] },
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

  const abortSignal = o?.abortSignal ?? ctx.abortSignal;
  if (abortSignal?.aborted) {
    yield { type: "start" };
    yield { type: "end", exitCode: 130, timedOut: false };
    return;
  }

  if (ctx.sandbox) {
    yield { type: "start" };
    const result = await ctx.sandbox.execute(cmd, {
      timeout: normalizeExecuteCommandTimeout(o?.timeoutSeconds),
      abortSignal,
      cwd: ctx.agentCwd,
      envVars: {
        ...readSandboxAgentEnv(),
        ...ctx.environmentVariables,
        ...o?.envVars,
      },
    });
    if (result.stdout)
      yield {
        type: "stdout",
        seq: 0,
        bytes: redactSecretValues(result.stdout, ctx.secretValues),
      };
    if (result.stderr)
      yield {
        type: "stderr",
        seq: 1,
        bytes: redactSecretValues(result.stderr, ctx.secretValues),
      };
    yield {
      type: "end",
      exitCode: result.exitCode,
      timedOut: result.exitCode === 124,
    };
    return;
  }

  const shell =
    ctx.commandShell ??
    new PerCommandShell({ cwd: ctx.agentCwd, env: ctx.environmentVariables });

  yield { type: "start" };

  const lifetime = new AbortController();
  const signal = abortSignal
    ? AbortSignal.any([abortSignal, lifetime.signal])
    : lifetime.signal;
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
  const execute = program
    ? shell.executeArgv.bind(shell, program.executable, program.args)
    : shell.execute.bind(shell, cmd);
  const execPromise = execute({
    cwd: ctx.agentCwd,
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
    abortSignal: signal,
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
        stdoutTruncated: res.stdoutTruncated,
        stderrTruncated: res.stderrTruncated,
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

  try {
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
  } finally {
    lifetime.abort();
    try {
      await execPromise;
    } finally {
      if (!ctx.commandShell) await shell.dispose();
    }
  }
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
  if (ctx.sandbox) {
    return requestSandboxHttp(
      { ...ctx, abortSignal: o?.abortSignal ?? ctx.abortSignal },
      {
        url: req.url,
        method,
        headers,
        body: req.body,
        followRedirects: req.followRedirects ?? false,
        timeout,
      },
    );
  }
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  try {
    const timeoutController = new AbortController();
    if (timeout !== undefined)
      timeoutId = setTimeout(() => timeoutController.abort(), timeout);
    const combinedSignal = o?.abortSignal
      ? AbortSignal.any([o.abortSignal, timeoutController.signal])
      : timeoutController.signal;
    const { response, redirectChain } = await targetFetch(
      resolverSessionFromCtx(ctx),
      req.url,
      {
        method,
        headers,
        body: req.body || undefined,
        redirect: req.followRedirects ? "follow" : "manual",
        signal: combinedSignal,
      },
    );
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });
    const read = await readHttpBodyCapped(
      response,
      5 * 1024 * 1024,
      combinedSignal,
    );
    const stopReason =
      read.stopReason === "aborted"
        ? o?.abortSignal?.aborted
          ? "aborted"
          : "timeout"
        : read.stopReason;
    const complete = stopReason === "end";
    const declaredRaw = response.headers.get("content-length");
    const declared = declaredRaw ? Number.parseInt(declaredRaw, 10) : NaN;
    const declaredBytes =
      Number.isSafeInteger(declared) && declared >= 0 ? declared : undefined;
    const error = complete
      ? undefined
      : stopReason === "timeout"
        ? `Request timeout after ${timeout}ms — partial body captured`
        : stopReason === "aborted"
          ? "Request aborted by user — partial body captured"
          : stopReason === "byte-cap"
            ? "download capped at 5242880 bytes — partial body captured"
            : errMessage(read.cause);
    return {
      success: complete,
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: read.text,
      url: response.url,
      redirected: redirectChain.length > 1,
      ...(redirectChain.length > 1 ? { redirectChain } : {}),
      error,
      capture: {
        complete,
        stopReason,
        capturedBytes: read.received,
        capturedBytesBasis: "raw",
        ...(declaredBytes !== undefined ? { declaredBytes } : {}),
      },
    };
  } catch (error: unknown) {
    const isAbort = error instanceof Error && error.name === "AbortError";
    const redirectChain =
      error instanceof TargetRedirectError ? error.redirectChain : undefined;
    const stopReason = isAbort
      ? o?.abortSignal?.aborted
        ? "aborted"
        : "timeout"
      : "error";
    return {
      success: false,
      error: isAbort
        ? o?.abortSignal?.aborted
          ? "Request aborted by user"
          : `Request timeout after ${timeout}ms`
        : errMessage(error),
      url: redirectChain?.at(-1) ?? req.url,
      method,
      status: 0,
      statusText: "",
      headers: {},
      body: "",
      redirected: (redirectChain?.length ?? 0) > 1,
      ...(redirectChain && redirectChain.length > 1 ? { redirectChain } : {}),
      capture: {
        complete: false,
        stopReason,
        capturedBytes: 0,
        capturedBytesBasis: "raw",
      },
    };
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
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
    o?.timeoutMs ?? CAPS.READABILITY_TIMEOUT_MS,
  );
  const combinedSignal = o?.abortSignal
    ? AbortSignal.any([o.abortSignal, controller.signal])
    : controller.signal;
  try {
    const session = resolverSessionFromCtx(ctx);
    const { response, redirectChain } = await fetchWithScopedRedirects(
      url,
      {
        method: "GET",
        signal: combinedSignal,
        redirect: "follow",
      },
      (hopUrl) =>
        mergeBaselineHeaders(resolveEffectiveHeaders(session, hopUrl)),
    );

    if (!response.ok) {
      response.body?.cancel().catch(() => {});
      return {
        success: false,
        url: response.url,
        status: response.status,
        statusText: response.statusText,
        headers: {},
        body: "",
        redirected: redirectChain.length > 1,
        ...(redirectChain.length > 1 ? { redirectChain } : {}),
        error: `Failed to fetch page: ${response.status} ${response.statusText}`,
      };
    }

    const contentType = response.headers.get("content-type") || "";
    if (
      !contentType.includes("text/html") &&
      !contentType.includes("text/plain") &&
      !contentType.includes("application/xhtml")
    ) {
      response.body?.cancel().catch(() => {});
      return {
        success: false,
        url: response.url,
        status: response.status,
        statusText: response.statusText,
        headers: {},
        body: "",
        redirected: redirectChain.length > 1,
        ...(redirectChain.length > 1 ? { redirectChain } : {}),
        error: `Unsupported content type: ${contentType}. This tool only supports HTML and text pages.`,
      };
    }

    const read = await readHttpBodyCapped(
      response,
      5 * 1024 * 1024,
      combinedSignal,
    );
    const producerStop =
      read.stopReason === "end"
        ? undefined
        : read.stopReason === "aborted"
          ? o?.abortSignal?.aborted
            ? "aborted"
            : "timeout"
          : read.stopReason;
    const html = read.text;
    const title = extractTitle(html);
    let content = extractTextContent(html);
    const previewTruncated = content.length > CAPS.READABILITY_MAX_CHARS;
    if (previewTruncated) {
      content = `${content.substring(0, CAPS.READABILITY_MAX_CHARS)}\n\n... (content truncated — page exceeded maximum length)`;
    }
    if (producerStop) {
      const error =
        producerStop === "timeout"
          ? `Request timeout after ${(o?.timeoutMs ?? CAPS.READABILITY_TIMEOUT_MS) / 1000}s — partial content extracted`
          : producerStop === "aborted"
            ? "Request aborted by user — partial content extracted"
            : producerStop === "byte-cap"
              ? "page download capped — full page not fetched"
              : errMessage(read.cause);
      return {
        success: false,
        url: response.url,
        title,
        status: response.status,
        statusText: response.statusText,
        headers: {},
        body: `${content}\n\n... (INCOMPLETE — ${error})`,
        redirected: redirectChain.length > 1,
        ...(redirectChain.length > 1 ? { redirectChain } : {}),
        error,
        contentTruncated: true,
        stopReason: producerStop,
      };
    }
    return {
      success: true,
      ...(previewTruncated
        ? { contentTruncated: true, stopReason: "content-limit" as const }
        : {}),
      url: response.url,
      title,
      status: response.status,
      statusText: response.statusText,
      headers: {},
      body: content,
      redirected: redirectChain.length > 1,
      ...(redirectChain.length > 1 ? { redirectChain } : {}),
    };
  } catch (error: unknown) {
    const isAbort = error instanceof Error && error.name === "AbortError";
    const redirectChain =
      error instanceof TargetRedirectError ? error.redirectChain : undefined;
    const errorMsg = isAbort
      ? o?.abortSignal?.aborted
        ? "Request aborted by user"
        : `Request timeout after ${CAPS.READABILITY_TIMEOUT_MS / 1000}s`
      : `Failed to fetch page: ${errMessage(error)}`;
    return {
      success: false,
      url: redirectChain?.at(-1) ?? url,
      status: 0,
      statusText: "",
      headers: {},
      body: "",
      redirected: (redirectChain?.length ?? 0) > 1,
      ...(redirectChain && redirectChain.length > 1 ? { redirectChain } : {}),
      error: errorMsg,
      contentTruncated: true,
      stopReason: isAbort
        ? o?.abortSignal?.aborted
          ? "aborted"
          : "timeout"
        : "error",
    };
  } finally {
    clearTimeout(timeoutId);
  }
}
