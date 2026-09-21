/**
 * `LocalBackends` — the apex (CLI/TUI) implementation of {@link ToolBackends}.
 *
 * Reproduces today's local behaviour byte-for-byte: filesystem via `node:fs`,
 * `command` via the shared `persistentShell`, `http` via `targetFetch` (plus
 * the `get_page` readability extract), `browser` via the local Playwright-MCP
 * toolset, and `inbox` via the #1051 seams. Every call consults a
 * {@link ToolPolicy} first; the default composes engagement scope and the
 * destructive-action block.
 */

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import {
  readFile as fsReadFile,
  mkdir,
  readdir,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import type { ToolCallOptions } from "ai";
import { glob as globAsync } from "glob";
import {
  applyHunksToContent,
  parseUnifiedDiff,
} from "../../agents/offSecAgent/tools/applyPatch";
import { runGit } from "../../agents/offSecAgent/tools/gitStatus";
import { createBrowserTools } from "../../agents/offSecAgent/tools/playwrightMcp";
import { resolverSessionFromCtx } from "../../agents/offSecAgent/tools/scopeGuard";
import { HttpSmsInbox } from "../../agents/offSecAgent/tools/smsInbox";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import { resolveEffectiveHeaders, targetFetch } from "../../http/targetHeaders";
import type { HeaderRecord } from "../../http/types";
import {
  CAPS,
  normalizeExecuteCommandTimeout,
  redactSecretValues,
  resolveAgentPath,
  resolveContained,
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
  FilePatchResult,
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
  WriteMode,
  WriteResult,
} from "./types";

// ---------------------------------------------------------------------------
// Filesystem constants (byte-identical to the tools they replace)
// ---------------------------------------------------------------------------

const GLOB_DEFAULT_IGNORE = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/build/**",
  "**/.next/**",
  "**/coverage/**",
  "**/__pycache__/**",
  "**/.venv/**",
  "**/venv/**",
];

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

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function wrapCommandWithEnv(
  command: string,
  envVars?: Record<string, string>,
): string {
  if (!envVars || Object.keys(envVars).length === 0) return command;
  const assignments = Object.entries(envVars)
    .map(([name, value]) => {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
        throw new Error(`Invalid environment variable name: ${name}`);
      }
      return `${name}=${shellQuote(value)}`;
    })
    .join(" ");
  return `env ${assignments} bash -lc ${shellQuote(command)}`;
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

async function readLocal(path: string): Promise<string | null> {
  try {
    return await fsReadFile(path, "utf-8");
  } catch {
    return null;
  }
}

async function writeLocal(path: string, content: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content, "utf-8");
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
      const resolved = resolveAgentPath(ctx.agentCwd, path);
      try {
        const raw = await fsReadFile(resolved, "utf-8");
        const allLines = raw.split("\n");
        const totalLines = allLines.length;
        const start = o?.startLine ? Math.max(1, o.startLine) : 1;
        const end = o?.endLine ? Math.min(totalLines, o.endLine) : totalLines;
        const selected = allLines.slice(start - 1, end);
        const numbered = selected
          .map((line, i) => `${String(start + i).padStart(6)}|${line}`)
          .join("\n");
        const capped =
          numbered.length > CAPS.READ_MAX_CHARS
            ? `${numbered.substring(0, CAPS.READ_MAX_CHARS)}\n\n(truncated — use startLine/endLine to paginate)`
            : numbered;
        return {
          success: true,
          error: "",
          content: capped,
          path,
          totalLines,
          linesReturned: selected.length,
        };
      } catch (err: unknown) {
        return { success: false, error: errMessage(err), content: "", path };
      }
    },

    async readRaw(path: string): Promise<RawReadResult> {
      await checkPolicy("fs", "readRaw", { path });
      const resolved = resolveAgentPath(ctx.agentCwd, path);
      try {
        const content = await fsReadFile(resolved, "utf-8");
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
      const base = dir ? resolveAgentPath(ctx.agentCwd, dir) : ctx.agentCwd;
      try {
        const info = await stat(base);
        if (!info.isDirectory()) {
          return {
            success: false,
            error: `${base} is not a directory`,
            files: [],
            directory: base,
            count: 0,
          };
        }

        if (o?.recursive) {
          const { paths, total } = await listRecursive(
            base,
            CAPS.LIST_MAX_RECURSIVE,
          );
          const relPaths = toRelative(base, paths);
          return {
            success: true,
            error:
              total > CAPS.LIST_MAX_RECURSIVE
                ? `Showing ${CAPS.LIST_MAX_RECURSIVE} of ${total} entries — narrow the directory or use grep`
                : "",
            files: relPaths,
            directory: base,
            count: relPaths.length,
            totalFound: total > CAPS.LIST_MAX_RECURSIVE ? total : undefined,
          };
        }

        const entries = await readdir(base, { withFileTypes: true });
        const fullPaths = entries.map((e) => {
          const name = join(base, e.name);
          return e.isDirectory() ? `${name}/` : name;
        });
        const cappedPaths = fullPaths.slice(0, CAPS.LIST_MAX_NON_RECURSIVE);
        const relPaths = toRelative(base, cappedPaths);
        return {
          success: true,
          error:
            entries.length > CAPS.LIST_MAX_NON_RECURSIVE
              ? `Showing ${CAPS.LIST_MAX_NON_RECURSIVE} of ${entries.length} entries`
              : "",
          files: relPaths,
          directory: base,
          count: relPaths.length,
          totalFound:
            entries.length > CAPS.LIST_MAX_NON_RECURSIVE
              ? entries.length
              : undefined,
        };
      } catch (err: unknown) {
        return {
          success: false,
          error: errMessage(err),
          files: [],
          directory: base,
          count: 0,
        };
      }
    },

    grep(q: GrepQuery): Promise<GrepResult> {
      return runGrep(ctx, q, checkPolicy);
    },

    async glob(pattern: string, o?: GlobOpts): Promise<GlobResult> {
      await checkPolicy("fs", "glob", { pattern, path: o?.path });
      let root: string;
      try {
        root = o?.path ? resolveContained(ctx.agentCwd, o.path) : ctx.agentCwd;
      } catch (err: unknown) {
        return {
          success: false,
          error: errMessage(err),
          files: [],
          count: 0,
          pattern,
          cwd: ctx.agentCwd,
        };
      }
      try {
        const matches = await globAsync(pattern, {
          cwd: root,
          nodir: true,
          dot: false,
          ignore: GLOB_DEFAULT_IGNORE,
          absolute: false,
        });
        const truncated = matches.length > CAPS.GLOB_MAX_RESULTS;
        const files = matches.slice(0, CAPS.GLOB_MAX_RESULTS).sort();
        return {
          success: true,
          error: truncated
            ? `Showing ${CAPS.GLOB_MAX_RESULTS} of ${matches.length} matches — narrow the pattern`
            : "",
          files,
          count: files.length,
          totalFound: truncated ? matches.length : undefined,
          pattern,
          cwd: root,
        };
      } catch (err: unknown) {
        return {
          success: false,
          error: errMessage(err),
          files: [],
          count: 0,
          pattern,
          cwd: root,
        };
      }
    },

    async write(
      path: string,
      content: string,
      o: { mode: WriteMode },
    ): Promise<WriteResult> {
      await checkPolicy("fs", "write", { path, mode: o.mode });
      const resolved = resolveAgentPath(ctx.agentCwd, path);
      const overwrite = o.mode === "overwrite";
      try {
        if (!overwrite && existsSync(resolved)) {
          return {
            success: false,
            error: `File already exists: ${resolved}. Set overwrite=true to replace it.`,
            path: resolved,
          };
        }
        await mkdir(dirname(resolved), { recursive: true });
        await writeFile(resolved, content, "utf-8");
        return { success: true, error: "", path: resolved };
      } catch (err: unknown) {
        return { success: false, error: errMessage(err), path: resolved };
      }
    },

    async delete(path: string): Promise<void> {
      await checkPolicy("fs", "delete", { path });
      const target = resolveContained(ctx.agentCwd, path);
      await unlink(target);
    },

    async applyPatch(diff: string): Promise<ApplyPatchResult> {
      await checkPolicy("fs", "applyPatch", {});
      let files: ReturnType<typeof parseUnifiedDiff>;
      try {
        files = parseUnifiedDiff(diff);
      } catch (err: unknown) {
        return { success: false, error: errMessage(err), files: [] };
      }

      const results: FilePatchResult[] = [];
      for (const file of files) {
        const displayPath = file.newPath || file.oldPath;
        try {
          const targetPath = resolveContained(
            ctx.agentCwd,
            file.isDelete ? file.oldPath : file.newPath || file.oldPath,
          );

          if (file.isDelete) {
            await unlink(targetPath);
            results.push({ path: displayPath, success: true, hunksApplied: 0 });
            continue;
          }

          const existing = await readLocal(targetPath);
          if (file.isNew) {
            if (existing !== null) {
              throw new Error(
                `Cannot create ${targetPath}: file already exists`,
              );
            }
            const created = applyHunksToContent("", file.hunks);
            await writeLocal(targetPath, created);
            results.push({
              path: displayPath,
              success: true,
              hunksApplied: file.hunks.length,
            });
            continue;
          }

          if (existing === null) {
            throw new Error(`File not found: ${targetPath}`);
          }
          const updated = applyHunksToContent(existing, file.hunks);
          await writeLocal(targetPath, updated);
          results.push({
            path: displayPath,
            success: true,
            hunksApplied: file.hunks.length,
          });
        } catch (err: unknown) {
          const message = errMessage(err);
          results.push({ path: displayPath, success: false, error: message });
          return {
            success: false,
            error: `Failed applying patch to ${displayPath}: ${message}`,
            files: results,
          };
        }
      }
      return { success: true, error: "", files: results };
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
// list_files helpers (byte-identical to listFiles.ts)
// ---------------------------------------------------------------------------

async function listRecursive(
  dir: string,
  maxEntries: number,
): Promise<{ paths: string[]; total: number }> {
  const results: string[] = [];
  let total = 0;
  async function walk(current: string) {
    let entries: import("node:fs").Dirent[];
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      total++;
      const fullPath = join(current, entry.name);
      if (entry.isDirectory()) {
        if (results.length < maxEntries) results.push(`${fullPath}/`);
        await walk(fullPath);
      } else {
        if (results.length < maxEntries) results.push(fullPath);
      }
    }
  }
  await walk(dir);
  return { paths: results, total };
}

function toRelative(base: string, paths: string[]): string[] {
  return paths.map((p) => {
    const isDir = p.endsWith("/");
    const rel = relative(base, isDir ? p.slice(0, -1) : p);
    return isDir ? `${rel}/` : rel;
  });
}

// ---------------------------------------------------------------------------
// grep (byte-identical to grep.ts)
// ---------------------------------------------------------------------------

function runGrep(
  ctx: ToolContext,
  { pattern, directory, flags }: GrepQuery,
  checkPolicy: (b: BackendName, op: string, args: unknown) => Promise<void>,
): Promise<GrepResult> {
  return (async () => {
    await checkPolicy("fs", "grep", { pattern, directory, flags });
    if (ctx.abortSignal?.aborted) {
      return {
        success: false,
        error: "Grep aborted by user",
        output: "",
        matchCount: 0,
        command: "",
      };
    }

    const dir = directory || ".";
    const cwd = ctx.agentCwd;
    const userFlags = flags ? flags.trim().split(/\s+/) : [];
    const hasRecursive = userFlags.some(
      (f) => /^-[a-zA-Z]*r[a-zA-Z]*$/.test(f) || f === "--recursive",
    );
    const defaultFlags = hasRecursive ? [] : ["-r"];
    const args = [...defaultFlags, ...userFlags, "--", pattern, dir];
    const command = `grep ${args.join(" ")}`;

    return new Promise<GrepResult>((resolveGrep) => {
      const child = spawn("grep", args, {
        cwd,
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      let resolved = false;

      let abortCleanup: (() => void) | undefined;
      if (ctx.abortSignal) {
        const abortHandler = () => child.kill("SIGTERM");
        ctx.abortSignal.addEventListener("abort", abortHandler, { once: true });
        abortCleanup = () =>
          ctx.abortSignal?.removeEventListener("abort", abortHandler);
      }

      const safeResolve = (result: GrepResult) => {
        if (resolved) return;
        resolved = true;
        clearTimeout(timeout);
        abortCleanup?.();
        resolveGrep(result);
      };

      const timeout = setTimeout(() => {
        child.kill("SIGTERM");
      }, CAPS.GREP_TIMEOUT_SECONDS * 1_000);

      child.stdout.on("data", (data) => {
        stdout += data.toString();
      });
      child.stderr.on("data", (data) => {
        stderr += data.toString();
      });
      child.on("close", (code) => {
        const noMatch = code === 1 && stderr === "";
        const matchCount = stdout ? stdout.trimEnd().split("\n").length : 0;
        const truncated = stdout.length > CAPS.GREP_MAX_CHARS;
        const output = truncated
          ? `${stdout.substring(0, CAPS.GREP_MAX_CHARS)}\n\n(truncated — narrow your search)`
          : stdout || "(no matches)";
        safeResolve({
          success: code === 0 || noMatch,
          error: noMatch || code === 0 ? "" : stderr || `Exit code: ${code}`,
          output,
          matchCount,
          command,
        });
      });
      child.on("error", (err) => {
        safeResolve({
          success: false,
          error: err.message,
          output: "",
          matchCount: 0,
          command,
        });
      });
    });
  })();
}

// ---------------------------------------------------------------------------
// command.run — persistentShell streamed as CommandEvents
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

  const shell = ctx.persistentShell;
  if (!shell) {
    yield { type: "start" };
    yield {
      type: "stderr",
      seq: 0,
      bytes: "No shell available (LocalBackends requires a persistentShell)",
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
  const wrapped = wrapCommandWithEnv(cmd, o?.envVars);

  // `onData` streams tail's best-effort live view of stdout as the command
  // runs; `res.stdout` (below) is the authoritative post-cutover recapture of
  // the same file, which can include trailing bytes tail's poll interval
  // missed. Track how much was already streamed so the remainder — not a
  // duplicate of the whole thing — closes the gap; a consumer that
  // concatenates every `stdout` event ends up with the authoritative text.
  let rawStreamedLen = 0;
  const execPromise = shell
    .execute(
      wrapped,
      normalized,
      (chunk: string) => {
        rawStreamedLen += chunk.length;
        queue.push({
          type: "stdout",
          seq: seq++,
          bytes: redactSecretValues(chunk, ctx.secretValues),
        });
        wake();
      },
      o?.abortSignal,
    )
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
