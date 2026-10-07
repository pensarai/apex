import { randomBytes } from "node:crypto";
import { tool } from "ai";
import { z } from "zod";
import { collectCommand } from "../../../tools/backends/collectCommand";
import { resolveBackends } from "../../../tools/backends/resolve";
import { resolveWhiteboxJobs } from "../../../tools/backends/whiteboxJobs";
import {
  readTextPrefix,
  resolveSessionWhiteboxArtifactPath,
  resolveWhiteboxCodebaseRoot,
  type WhiteboxJobRecord,
  writeWhiteboxArtifact,
} from "../../../whitebox";
import { assertCommandInScope, ScopeViolationError } from "./scopeGuard";
import type { ToolContext } from "./types";

const NODE_CHECK_TIMEOUT_SECONDS = 10;
const READINESS_TIMEOUT_MS = 15_000;
const READINESS_POLL_MS = 150;
const PROBE_TIMEOUT_SECONDS = 10;
const DEFAULT_LISTENER_TIMEOUT_SECONDS = 600;
const MAX_LISTENER_TIMEOUT_SECONDS = 3_600;
const INLINE_RECENT_HITS = 25;
const INLINE_BODY_CHARS = 256;

// The executed listener is the generated source embedded as inline base64
// in a `node -e` bootstrap, mirroring the job-control transport's shell
// split (POSIX sh needs the space-free payload quoted; cmd.exe verbatim
// does not). Base64 has no quote/percent characters and the jobs contract
// carries neither env nor paths, so nothing else needs quoting. The nonce
// rides inside the payload and therefore inside the job's start identity.
function bootstrapCommand(source: string, platform: string): string {
  const payload = `eval(Buffer.from('${Buffer.from(source, "utf8").toString("base64")}','base64').toString('utf8'))`;
  return platform === "windows" ? `node -e ${payload}` : `node -e "${payload}"`;
}

// Readiness probe: same shell split; the payload rides an env var through
// the regular command seam (which, unlike the jobs contract, carries env).
function probeCommand(platform: string): string {
  const payload =
    "eval(Buffer.from(process.env.APEX_CB_PROBE,'base64').toString('utf8'))";
  return platform === "windows" ? `node -e ${payload}` : `node -e "${payload}"`;
}

export type CallbackHit = {
  ts: string;
  method: string;
  path: string;
  source: "callback" | "selftest" | "unrelated";
  ip: string;
  body: string;
  bodyCapped?: boolean;
};

export type CallbackLogEvidence = {
  listening?: { bind: string; port: number; nonce: string };
  bindFailed?: { code: string; detail: string };
  hits: CallbackHit[];
};

const HIT_PREFIX = "[apex-callback] hit ";
const LISTENING_PREFIX = "[apex-callback] listening ";
const BIND_FAILED_PREFIX = "[apex-callback] bind-failed ";

/** Validate and normalize one parsed hit record; undefined for malformed. */
function asCallbackHit(value: unknown): CallbackHit | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const rec = value as CallbackHit;
  if (
    typeof rec.ts !== "string" ||
    typeof rec.method !== "string" ||
    typeof rec.path !== "string" ||
    (rec.source !== "callback" &&
      rec.source !== "selftest" &&
      rec.source !== "unrelated") ||
    typeof rec.ip !== "string" ||
    typeof rec.body !== "string"
  ) {
    return undefined;
  }
  return {
    ts: rec.ts,
    method: rec.method,
    path: rec.path.slice(0, 512),
    source: rec.source,
    ip: rec.ip,
    body: rec.body,
    ...(rec.bodyCapped ? { bodyCapped: true } : {}),
  };
}

/** Parse the listener's structured log lines (one JSON hit per line). */
export function parseCallbackListenerLog(content: string): CallbackLogEvidence {
  const evidence: CallbackLogEvidence = { hits: [] };
  for (const line of content.split("\n")) {
    if (line.startsWith(LISTENING_PREFIX)) {
      const bind = / bind=([^ ]+)/.exec(line)?.[1];
      const port = Number(/ port=(\d+)/.exec(line)?.[1]);
      const nonce = / nonce=([a-f0-9]+)/.exec(line)?.[1];
      if (bind && Number.isInteger(port) && port > 0 && nonce) {
        evidence.listening = { bind, port, nonce };
      }
    } else if (line.startsWith(HIT_PREFIX)) {
      try {
        const hit = asCallbackHit(JSON.parse(line.slice(HIT_PREFIX.length)));
        if (hit) evidence.hits.push(hit);
      } catch {
        // Partial line at the log-tail boundary — skip.
      }
    } else if (line.startsWith(BIND_FAILED_PREFIX)) {
      evidence.bindFailed = {
        code: / code=([^ ]*)/.exec(line)?.[1] ?? "",
        detail: line.slice(BIND_FAILED_PREFIX.length).slice(0, 400),
      };
    }
  }
  return evidence;
}

/**
 * The generated listener (Node built-ins only, config embedded). It runs
 * via the embedded bootstrap; the staged `.cjs` copy is the audit artifact
 * (and stays CommonJS even inside a `type: module` workspace). The nonce is
 * the only ownership claim: correlated paths echo it, others get a 404.
 */
export function buildCallbackListenerScript(config: {
  port: number;
  bindAddress: string;
  nonce: string;
}): string {
  return [
    '"use strict";',
    "// Apex callback listener (generated). Config is embedded below.",
    `const port = ${config.port};`,
    `const bind = ${JSON.stringify(config.bindAddress)};`,
    `const nonce = ${JSON.stringify(config.nonce)};`,
    "const http = require('node:http');",
    "const MAX_BODY_BYTES = 2048;",
    "if (!/^[a-f0-9]{16,64}$/.test(nonce) || !Number.isInteger(port) || port < 0 || port > 65535 || !/^[A-Za-z0-9._:-]+$/.test(bind)) {",
    "  process.stdout.write('[apex-callback] bind-failed code=BAD_ARGS invalid nonce, port, or bind address\\n');",
    "  process.exit(2);",
    "}",
    "const server = http.createServer(function (req, res) {",
    "  const chunks = [];",
    "  let size = 0;",
    "  req.on('data', function (c) { if (size < MAX_BODY_BYTES) chunks.push(c); size += c.length; });",
    "  req.on('error', function () {});",
    "  req.on('end', function () {",
    "    let path = req.url || '/';",
    "    if (path.length > 512) path = path.slice(0, 512);",
    "    const correlated = path === '/' + nonce || path.slice(0, nonce.length + 2) === '/' + nonce + '/';",
    "    const selftest = correlated && path === '/' + nonce + '/__apex_ready__';",
    "    process.stdout.write('[apex-callback] hit ' + JSON.stringify({",
    "      ts: new Date().toISOString(), method: req.method, path: path,",
    "      source: selftest ? 'selftest' : correlated ? 'callback' : 'unrelated',",
    "      ip: (req.socket && req.socket.remoteAddress) || '',",
    "      body: Buffer.concat(chunks).toString('utf8').slice(0, MAX_BODY_BYTES),",
    "      bodyCapped: size > MAX_BODY_BYTES,",
    "    }) + '\\n');",
    "    res.statusCode = correlated ? 200 : 404;",
    "    res.setHeader('content-type', 'text/plain');",
    "    res.end(correlated ? 'apex-callback ' + nonce : 'not found');",
    "  });",
    "});",
    "server.on('error', function (e) {",
    "  process.stdout.write('[apex-callback] bind-failed code=' + ((e && e.code) || '') + ' ' + String((e && e.message) || '').slice(0, 200) + '\\n');",
    "  process.exit(1);",
    "});",
    "server.listen(port, bind, function () {",
    "  const a = server.address();",
    "  process.stdout.write('[apex-callback] listening bind=' + bind + ' port=' + ((a && a.port) || 0) + ' nonce=' + nonce + '\\n');",
    "});",
    "",
  ].join("\n");
}

/** Loopback probe URL for the listener's own bind address (IPv6 bracketed). */
export function probeUrlFor(bindAddress: string, port: number, nonce: string) {
  const host =
    bindAddress === "0.0.0.0"
      ? "127.0.0.1"
      : bindAddress === "::"
        ? "[::1]"
        : bindAddress.includes(":")
          ? `[${bindAddress}]`
          : bindAddress;
  return `http://${host}:${port}/${nonce}/__apex_ready__`;
}

export type CallbackListenerHandle = {
  jobId: string;
  nonce: string;
  scriptPath: string;
  bindAddress: string;
  port: number;
  advertisedBaseUrl?: string;
  /** Set once a nonce self-test confirmed through the command seam. */
  selfTestConfirmed: boolean;
  artifactPath?: string;
  /** Identity of the last persisted snapshot; content-based, not hit-count. */
  lastPersistedSnapshot?: string;
  /** Stops exactly this listener; abort signal cleared for post-abort cleanup. */
  stop: () => Promise<WhiteboxJobRecord | undefined>;
};

/**
 * Per-agent listener registry. Tools require a handle from it — a job id
 * alone never authorizes poll/stop — and the agent's finalization drains
 * it so cleanup survives an abort.
 */
export class CallbackListenerRegistry {
  private readonly handles = new Map<string, CallbackListenerHandle>();

  register(handle: CallbackListenerHandle): void {
    this.handles.set(handle.jobId, handle);
  }

  get(jobId: string): CallbackListenerHandle | undefined {
    return this.handles.get(jobId);
  }

  remove(jobId: string): void {
    this.handles.delete(jobId);
  }

  /**
   * Best-effort stop of every listener; each outcome independent. Only
   * successfully cleaned handles are removed — a failed stop stays
   * registered so the next cleanup path (finalizeRun after abortAndDrain)
   * can retry that owner.
   */
  async stopAll(): Promise<Array<{ jobId: string; error?: string }>> {
    const outcomes: Array<{ jobId: string; error?: string }> = [];
    for (const handle of [...this.handles.values()]) {
      try {
        await handle.stop();
        this.handles.delete(handle.jobId);
        outcomes.push({ jobId: handle.jobId });
      } catch (error: unknown) {
        outcomes.push({
          jobId: handle.jobId,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    return outcomes;
  }
}

/**
 * Compose the nonce callback URL from an advertised base, path-aware: the
 * base's route prefix is kept, its query (tokenized routes) stays after the
 * path, and fragments are stripped — HTTP clients never send them.
 */
export function composeCallbackUrl(
  advertisedBaseUrl: string,
  nonce: string,
): string | undefined {
  try {
    const url = new URL(advertisedBaseUrl);
    const route = url.pathname.replace(/\/+$/, "");
    url.pathname = `${route}/${nonce}/cb`;
    url.hash = "";
    return url.toString();
  } catch {
    return undefined;
  }
}

function callbackUrlFor(handle: {
  nonce: string;
  advertisedBaseUrl?: string;
}): string | undefined {
  return handle.advertisedBaseUrl
    ? composeCallbackUrl(handle.advertisedBaseUrl, handle.nonce)
    : undefined;
}

function summarizeEvidence(evidence: CallbackLogEvidence) {
  const callbacks = evidence.hits.filter((h) => h.source === "callback");
  return {
    callbackHits: callbacks.length,
    selfTestHits: evidence.hits.filter((h) => h.source === "selftest").length,
    unrelatedHits: evidence.hits.filter((h) => h.source === "unrelated").length,
    recentHits: callbacks.slice(-INLINE_RECENT_HITS).map((h) => ({
      ts: h.ts,
      method: h.method,
      path: h.path,
      ip: h.ip,
      body: h.body.slice(0, INLINE_BODY_CHARS),
      ...(h.body.length > INLINE_BODY_CHARS || h.bodyCapped
        ? { bodyTruncated: true }
        : {}),
    })),
  };
}

/** Cleanup seam: abort cleared so an already-aborted run can still stop. */
function jobsSeamForCleanup(ctx: ToolContext) {
  return resolveWhiteboxJobs({ ...ctx, abortSignal: undefined });
}

const PROBE_SOURCE = Buffer.from(
  [
    '"use strict";',
    "const http = require('node:http');",
    "const req = http.get(process.env.APEX_CB_PROBE_URL || '', function (res) {",
    "  let body = '';",
    "  res.setEncoding('utf8');",
    "  res.on('data', function (c) { body += c; });",
    "  res.on('end', function () { process.stdout.write(body); process.exit(0); });",
    "});",
    "req.on('error', function (e) { process.stderr.write(String((e && e.message) || e)); process.exit(1); });",
    "setTimeout(function () { process.stderr.write('probe timeout'); process.exit(1); }, 8000).unref();",
    "",
  ].join("\n"),
  "utf8",
).toString("base64");

/**
 * Nonce readiness probe through the command seam — the same environment
 * the listener runs in. Readiness is established only by a response that
 * echoes the nonce; a log line or an open port never confirms it.
 */
async function runNonceProbe(
  ctx: ToolContext,
  handle: CallbackListenerHandle,
): Promise<boolean> {
  try {
    const command = resolveBackends(ctx).command;
    const probe = await collectCommand(
      command.run(probeCommand(command.platform ?? "posix"), {
        timeoutSeconds: PROBE_TIMEOUT_SECONDS,
        envVars: {
          ...ctx.environmentVariables,
          APEX_CB_PROBE: PROBE_SOURCE,
          APEX_CB_PROBE_URL: probeUrlFor(
            handle.bindAddress,
            handle.port,
            handle.nonce,
          ),
        },
        abortSignal: ctx.abortSignal,
      }),
    );
    return probe.exitCode === 0 && probe.stdout.includes(handle.nonce);
  } catch {
    return false;
  }
}

/**
 * Stop one owned listener and report the real outcome — never a silent
 * "stopped" after a caught error. Handles stay registered after success
 * (evidence remains pollable); a failed stop keeps them for finalization.
 */
async function stopListenerReporting(
  handle: CallbackListenerHandle,
): Promise<string> {
  try {
    const record = await handle.stop();
    return record
      ? `listener stopped (status ${record.status})`
      : "stop returned no record (job already gone)";
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    return `stop failed: ${msg} — handle kept for finalization cleanup`;
  }
}

async function persistEvidenceSnapshot(input: {
  ctx: ToolContext;
  handle: CallbackListenerHandle;
  status: string;
  evidence: CallbackLogEvidence;
  logTruncated: boolean;
}): Promise<string | undefined> {
  const content = JSON.stringify(
    {
      jobId: input.handle.jobId,
      nonce: input.handle.nonce,
      bindAddress: input.handle.bindAddress,
      port: input.handle.port,
      status: input.status,
      logTruncated: input.logTruncated,
      listening: input.evidence.listening,
      bindFailed: input.evidence.bindFailed,
      hits: input.evidence.hits,
    },
    null,
    2,
  );
  // Content identity, not hit count: a rotated log tail can swap old hits
  // for new ones without changing the count.
  if (input.handle.lastPersistedSnapshot === content) {
    return input.handle.artifactPath;
  }
  try {
    const ref = await writeWhiteboxArtifact({
      session: input.ctx.session,
      area: "scratchpad",
      type: "raw-output",
      name: `callback-evidence-${input.handle.jobId}`,
      description: "Callback listener evidence snapshot (bounded)",
      content,
    });
    input.handle.artifactPath = ref.path;
    input.handle.lastPersistedSnapshot = content;
    return ref.path;
  } catch {
    return undefined;
  }
}

// Retained snapshots are read through the bounded session-artifact prefix
// seam, capped at one million UTF-16 code units (readTextPrefix counts
// chars, not bytes); truncation is detected before parsing.
const MAX_SNAPSHOT_READ_CHARS = 1_000_000;

type SnapshotRead =
  | { kind: "ok"; evidence: CallbackLogEvidence; logTruncated: boolean }
  | { kind: "absent" }
  | { kind: "unreadable"; reason: string };

/**
 * Read a retained evidence snapshot through the session-artifact seam —
 * the same owner/path resolver and bounded prefix IO that wrote it. A
 * missing file is absent; anything else that defeats the read is reported
 * as unreadable with its reason, never as absence.
 */
async function readSnapshotEvidence(
  session: { rootPath: string },
  artifactPath: string,
): Promise<SnapshotRead> {
  let absolute: string;
  try {
    absolute = resolveSessionWhiteboxArtifactPath({
      sessionRootPath: session.rootPath,
      artifactRelativePath: artifactPath,
    });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    return { kind: "unreadable", reason: `path rejected: ${msg}` };
  }
  let read: { content: string; truncated: boolean };
  try {
    read = await readTextPrefix(absolute, MAX_SNAPSHOT_READ_CHARS);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") {
      return { kind: "absent" };
    }
    const msg = error instanceof Error ? error.message : String(error);
    return { kind: "unreadable", reason: `read failed: ${msg}` };
  }
  // Truncation is checked before parsing: a cut JSON body cannot parse and
  // must be reported as capped, not as corrupt or absent.
  if (read.truncated) {
    return {
      kind: "unreadable",
      reason: `exceeds the bounded read cap of ${MAX_SNAPSHOT_READ_CHARS} chars`,
    };
  }
  try {
    const parsed = JSON.parse(read.content) as {
      hits?: unknown;
      listening?: CallbackLogEvidence["listening"];
      bindFailed?: CallbackLogEvidence["bindFailed"];
      logTruncated?: boolean;
    };
    // A snapshot this helper wrote always carries an array of valid hit
    // entries; anything else is corruption, never a zero/partial success.
    if (!Array.isArray(parsed.hits)) {
      return { kind: "unreadable", reason: "corrupt (hits is not an array)" };
    }
    const hits: CallbackHit[] = [];
    for (const entry of parsed.hits) {
      const hit = asCallbackHit(entry);
      if (!hit) {
        return {
          kind: "unreadable",
          reason: "corrupt (malformed hit entry)",
        };
      }
      hits.push(hit);
    }
    return {
      kind: "ok",
      evidence: {
        listening: parsed.listening,
        bindFailed: parsed.bindFailed,
        hits,
      },
      logTruncated: parsed.logTruncated === true,
    };
  } catch {
    return { kind: "unreadable", reason: "corrupt (not valid JSON)" };
  }
}

/** Read the live job log for an owned handle; `gone` = no live record. */
async function readListenerLog(
  ctx: ToolContext,
  handle: CallbackListenerHandle,
): Promise<
  | {
      ok: true;
      record?: WhiteboxJobRecord;
      evidence: CallbackLogEvidence;
      logTruncated: boolean;
      gone: boolean;
    }
  | { ok: false; summary: string; artifactPath?: string }
> {
  const jobs = resolveWhiteboxJobs(ctx);
  let record: WhiteboxJobRecord | undefined;
  try {
    record = await jobs.poll(handle.jobId);
    if (record) {
      const log = await jobs.read(handle.jobId);
      return {
        ok: true,
        record,
        evidence: parseCallbackListenerLog(log.content),
        logTruncated: log.truncated,
        gone: false,
      };
    }
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    return { ok: false, summary: `Listener log read failed: ${msg}` };
  }
  // Record gone (pruned/expired): the persisted snapshot is retrieval-only.
  if (handle.artifactPath) {
    const snapshot = await readSnapshotEvidence(
      ctx.session,
      handle.artifactPath,
    );
    if (snapshot.kind === "ok") {
      return {
        ok: true,
        evidence: snapshot.evidence,
        logTruncated: snapshot.logTruncated,
        gone: true,
      };
    }
    if (snapshot.kind === "unreadable") {
      return {
        ok: false,
        summary: `Listener ${handle.jobId}'s retained evidence snapshot could not be read (${snapshot.reason}); the snapshot is preserved for direct inspection.`,
        artifactPath: handle.artifactPath,
      };
    }
  }
  return {
    ok: false,
    summary: `Listener ${handle.jobId} has no live job record and no persisted evidence snapshot.`,
  };
}

// Remote supervisor ids are wjob_<64 hex>; the in-process kernel also mints
// wjob_<epoch>_<hex> ids. Both spellings name a listener this agent started.
const callbackListenerJobIdSchema = z
  .string()
  .regex(
    /^wjob_(?:[a-f0-9]{64}|\d+_[a-f0-9]{1,16})$/,
    "Job id must come from start_callback_listener",
  );

const bindAddressSchema = z
  .string()
  .regex(
    /^[A-Za-z0-9._:-]+$/,
    "Bind address must be an IP address or hostname (no shell metacharacters)",
  );

function failureResult(
  summary: string,
  nextActions?: string[],
  data?: { jobId: string; artifactPath?: string },
) {
  return {
    success: false as const,
    summary,
    artifactPaths: data?.artifactPath ? [data.artifactPath] : [],
    nextActions: nextActions ?? ["Inspect the error, adjust, and retry."],
    ...(data ? { data } : {}),
  };
}

function unknownListenerResult(jobId: string) {
  return failureResult(
    `Listener ${jobId} is not owned by this agent. Only listeners started by this agent's start_callback_listener can be polled or stopped.`,
    ["Use start_callback_listener to start one, or check the job id."],
  );
}

export function startCallbackListener(ctx: ToolContext) {
  return tool({
    description: `Start a nonce-correlated HTTP callback listener for blind/out-of-band testing (SSRF, blind RCE, XSS callbacks).

The listener runs as a bounded whitebox job in the selected execution environment (sandbox/remote/local — never a host fallback) and survives intervening tool calls. Its port answers ONLY paths under its secret nonce; unrelated requests get a 404 and are counted separately, so an open port that belongs to someone else can never masquerade as your listener. Readiness is confirmed by a nonce self-test executed in the same environment — self-test hits are never target evidence.

Bind address and advertised URL are distinct: the listener binds where it runs (default 0.0.0.0, ephemeral port); the URL you embed in payloads must be an address the TARGET can reach. Supply advertisedBaseUrl only when you know one (an operator-provided route or a reachable host) — it is never guessed for you. Poll evidence with poll_callback_listener; stop with stop_callback_listener. The listener dies at its timeoutSeconds deadline at the latest.`,
    inputSchema: z.object({
      port: z
        .number()
        .int()
        .min(0)
        .max(65535)
        .optional()
        .describe(
          "Port to bind (0 = ephemeral, default). Fixed ports risk conflicts.",
        ),
      bindAddress: bindAddressSchema
        .optional()
        .describe("Bind address for the listener (default 0.0.0.0)."),
      advertisedBaseUrl: z
        .string()
        .url()
        .refine((v) => /^https?:\/\//.test(v), {
          message: "advertisedBaseUrl must be an http(s) URL",
        })
        .optional()
        .describe(
          "Base URL the TARGET can reach (e.g. an operator-provided callback route), used only to compose the callback URL returned to you. Never guessed. Route prefix and query parameters are preserved; fragments are stripped (HTTP clients never send them).",
        ),
      timeoutSeconds: z
        .number()
        .int()
        .min(10)
        .max(MAX_LISTENER_TIMEOUT_SECONDS)
        .optional()
        .describe(
          `Listener lifetime bound in seconds (default ${DEFAULT_LISTENER_TIMEOUT_SECONDS}, max ${MAX_LISTENER_TIMEOUT_SECONDS}).`,
        ),
      toolCallDescription: z
        .string()
        .describe("A concise description of what this listener is for"),
    }),
    execute: async (
      {
        port = 0,
        bindAddress = "0.0.0.0",
        advertisedBaseUrl,
        timeoutSeconds = DEFAULT_LISTENER_TIMEOUT_SECONDS,
      },
      options,
    ) => {
      if (!ctx.callbackListeners) {
        return failureResult(
          "Callback listeners require the agent's listener registry (owner-tracked cleanup); this tool context has none.",
        );
      }
      if (ctx.abortSignal?.aborted) {
        return failureResult("Listener start aborted by user before dispatch.");
      }

      const command = resolveBackends(ctx).command;

      // Preflight: the listener is a Node script; Node must exist in the
      // selected execution environment. Unsupported is reported, never
      // turned into false readiness.
      let nodeVersion: string | undefined;
      try {
        const checked = await collectCommand(
          command.run("node --version", {
            timeoutSeconds: NODE_CHECK_TIMEOUT_SECONDS,
            envVars: ctx.environmentVariables,
            abortSignal: ctx.abortSignal,
          }),
        );
        if (checked.exitCode !== 0 || checked.timedOut) {
          return failureResult(
            `Callback listeners are unavailable: Node.js is not available in the selected execution environment (node --version exit ${checked.exitCode}${checked.timedOut ? ", timed out" : ""}: ${checked.stderr.trim().slice(0, 200) || "no stderr"}).`,
            ["Use a probe technique that does not need a local listener."],
          );
        }
        nodeVersion = checked.stdout.trim().split("\n").pop()?.trim();
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return failureResult(
          `Callback listeners are unavailable: Node.js check failed: ${msg}`,
        );
      }

      const nonce = randomBytes(16).toString("hex");
      // One generated source, staged for audit AND embedded in the job
      // command — the jobs contract carries neither env vars nor paths.
      const listenerSource = buildCallbackListenerScript({
        port,
        bindAddress,
        nonce,
      });
      const write = await resolveBackends(ctx).fs.write(
        `callback-listeners/listener-${nonce}.cjs`,
        listenerSource,
        { mode: "overwrite" },
      );
      if (!write.success) {
        return failureResult(
          `Failed to stage the listener script in the helper workspace: ${write.error}`,
        );
      }

      let cwd: string;
      try {
        // Same cwd contract as start_whitebox_job: jobs run inside the
        // configured codebase root; the staged script is the audit copy.
        cwd = resolveWhiteboxCodebaseRoot({
          agentCwd: ctx.agentCwd,
          codebasePath: ctx.session.config?.codebasePath,
        });
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return failureResult(msg);
      }
      const listenerCommand = bootstrapCommand(
        listenerSource,
        command.platform ?? "posix",
      );
      try {
        assertCommandInScope(listenerCommand, ctx);
      } catch (error: unknown) {
        if (error instanceof ScopeViolationError) {
          return failureResult(error.message);
        }
        throw error;
      }

      const jobs = resolveWhiteboxJobs(ctx);
      let record: WhiteboxJobRecord;
      try {
        record = await jobs.start(
          {
            command: listenerCommand,
            cwd,
            timeoutSeconds,
            name: "callback-listener",
          },
          options.toolCallId,
        );
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return failureResult(`Listener job failed to start: ${msg}`, [
          "The job supervisor reports backend and path-policy failures verbatim.",
        ]);
      }

      // Ownership registers immediately after start — before readiness —
      // so an abort during startup still leaves a cleanable handle.
      const handle: CallbackListenerHandle = {
        jobId: record.id,
        nonce,
        scriptPath: write.path,
        bindAddress,
        port,
        ...(advertisedBaseUrl ? { advertisedBaseUrl } : {}),
        selfTestConfirmed: false,
        stop: () => jobsSeamForCleanup(ctx).stop(record.id),
      };
      ctx.callbackListeners.register(handle);

      // Readiness is distinct from "spawned": the listener's own listening
      // line, then a nonce probe through the same command environment.
      const deadline = Date.now() + READINESS_TIMEOUT_MS;
      let evidence: CallbackLogEvidence = { hits: [] };
      let status = record.status;
      while (Date.now() < deadline) {
        if (ctx.abortSignal?.aborted) {
          const stopReport = await stopListenerReporting(handle);
          return failureResult(
            `Listener start aborted by user during startup; ${stopReport}.`,
            undefined,
            { jobId: handle.jobId },
          );
        }
        try {
          const polled = await jobs.poll(handle.jobId);
          status = polled?.status ?? status;
          const log = await jobs.read(handle.jobId);
          evidence = parseCallbackListenerLog(log.content);
          if (evidence.listening) break;
          if (!polled || polled.status !== "running") break;
        } catch (error: unknown) {
          const msg = error instanceof Error ? error.message : String(error);
          const stopReport = await stopListenerReporting(handle);
          return failureResult(
            `Listener startup could not be confirmed: ${msg}; ${stopReport}.`,
            undefined,
            { jobId: handle.jobId },
          );
        }
        await new Promise((r) => setTimeout(r, READINESS_POLL_MS));
      }

      if (
        evidence.bindFailed ||
        (!evidence.listening && status !== "running")
      ) {
        // The job is dead (bind conflict or startup error) — nothing to stop.
        ctx.callbackListeners.remove(handle.jobId);
        const code = evidence.bindFailed?.code ?? "";
        const detail =
          evidence.bindFailed?.detail ?? `listener exited (${status})`;
        return failureResult(
          code === "EADDRINUSE"
            ? `Port conflict: the listener could not bind ${bindAddress}:${port} (EADDRINUSE).`
            : `Listener startup failed: ${detail}`,
          code === "EADDRINUSE"
            ? ["Retry with port 0 (ephemeral) or another free port."]
            : ["Inspect the failure detail and retry."],
          { jobId: handle.jobId },
        );
      }

      if (evidence.listening) {
        // The running listener's own log line is authoritative for the
        // effective port and nonce (idempotent restarts of the same request).
        handle.port = evidence.listening.port;
        handle.nonce = evidence.listening.nonce;
      }

      let selfTest: "confirmed" | "unconfirmed" | "not-listening" =
        "not-listening";
      if (evidence.listening) {
        if (await runNonceProbe(ctx, handle)) {
          selfTest = "confirmed";
          handle.selfTestConfirmed = true;
        } else {
          selfTest = "unconfirmed";
        }
      }

      // Readiness requires the nonce response AND a process that is still
      // running — a listener that died between probe and return is not ready.
      const finalStatus = (await jobs.poll(handle.jobId))?.status;
      const listenerReady =
        handle.selfTestConfirmed && finalStatus === "running";
      const callbackUrl = callbackUrlFor(handle);
      return {
        success: true,
        summary: listenerReady
          ? `Callback listener ready on ${handle.bindAddress}:${handle.port} (job ${handle.jobId}, nonce ${handle.nonce}).${callbackUrl ? ` Callback URL: ${callbackUrl}` : " No advertised URL supplied — use one only when you know an address the target can reach."}`
          : `Listener job ${handle.jobId} is ${finalStatus ?? "no longer reporting"} but readiness is ${selfTest === "not-listening" ? "not confirmed (no listening line yet)" : "unconfirmed (nonce self-test did not succeed)"}. It stays registered for cleanup; poll again or stop it.`,
        data: {
          listener: {
            jobId: handle.jobId,
            nonce: handle.nonce,
            spawned: true,
            bindAddress: handle.bindAddress,
            port: handle.port,
            requestedPort: port,
            timeoutSeconds,
            nodeVersion,
          },
          listenerReady,
          selfTest,
          listening: evidence.listening ?? null,
          callbackUrl: callbackUrl ?? null,
        },
        artifactPaths: record.logPath ? [record.logPath] : [],
        nextActions: listenerReady
          ? [
              callbackUrl
                ? `Embed ${callbackUrl} in payloads, then poll ${handle.jobId} with poll_callback_listener.`
                : `Poll ${handle.jobId} with poll_callback_listener once you have embedded a reachable URL under path /${handle.nonce}/.`,
              "Stop the listener with stop_callback_listener when done.",
            ]
          : [
              `Poll ${handle.jobId} with poll_callback_listener to check readiness later, or stop it.`,
            ],
        truncated: false,
      };
    },
  });
}

export function pollCallbackListener(ctx: ToolContext) {
  return tool({
    description: `Poll an owned callback listener and read its evidence.

Returns job status, listener readiness (only true while the process is running AND the nonce self-test succeeded), and nonce-correlated callback hits (method, path, source IP, bounded body preview). The tool's own self-test and traffic that misses the nonce path are reported separately and never counted as target callbacks. When the job record has expired, the last persisted evidence snapshot is shown instead. Output is bounded; the full window is persisted under scratchpad/whitebox.`,
    inputSchema: z.object({
      jobId: callbackListenerJobIdSchema,
      toolCallDescription: z
        .string()
        .describe("A concise description of this poll"),
    }),
    execute: async ({ jobId }) => {
      const handle = ctx.callbackListeners?.get(jobId);
      if (!handle) return unknownListenerResult(jobId);

      const read = await readListenerLog(ctx, handle);
      if (!read.ok) {
        return failureResult(read.summary, undefined, {
          jobId,
          ...(read.artifactPath ? { artifactPath: read.artifactPath } : {}),
        });
      }

      // A late listening line carries the effective (possibly ephemeral)
      // port — adopt it before probing so the probe targets the listener.
      if (read.evidence.listening) {
        handle.port = read.evidence.listening.port;
        handle.nonce = read.evidence.listening.nonce;
      }
      // Readiness holds only while the process runs and a nonce RESPONSE
      // confirmed it. A previously unconfirmed listener gets one bounded
      // probe here; a selftest log line alone never promotes readiness.
      const running = !read.gone && read.record?.status === "running";
      if (running && !handle.selfTestConfirmed) {
        handle.selfTestConfirmed = await runNonceProbe(ctx, handle);
      }
      const listenerReady = running && handle.selfTestConfirmed;

      const artifactPath = read.gone
        ? handle.artifactPath
        : ((await persistEvidenceSnapshot({
            ctx,
            handle,
            status: read.record?.status ?? "unknown",
            evidence: read.evidence,
            logTruncated: read.logTruncated,
          })) ?? handle.artifactPath);

      const summary = summarizeEvidence(read.evidence);
      const callbackUrl = callbackUrlFor(handle);
      return {
        success: true,
        summary: read.gone
          ? `Listener ${jobId} is no longer live; showing the persisted evidence snapshot (${summary.callbackHits} nonce-correlated callback${summary.callbackHits === 1 ? "" : "s"} observed).`
          : `Listener ${jobId} is ${read.record?.status ?? "unknown"}${listenerReady ? ", listener-ready" : ""}: ${summary.callbackHits} nonce-correlated callback${summary.callbackHits === 1 ? "" : "s"}, ${summary.unrelatedHits} unrelated request${summary.unrelatedHits === 1 ? "" : "s"}. Readiness and the tool's own self-test are never counted as target callbacks.`,
        data: {
          jobId,
          status: read.gone ? "record-gone" : read.record?.status,
          listenerReady,
          nonce: handle.nonce,
          bindAddress: handle.bindAddress,
          port: handle.port,
          callbackUrl: callbackUrl ?? null,
          ...summary,
          ...(read.logTruncated
            ? {
                logWindowTruncated: true,
                note: "Counts cover the visible tail of the bounded job log (lower bounds).",
              }
            : {}),
        },
        artifactPaths: artifactPath ? [artifactPath] : [],
        nextActions: [
          "Keep polling while the callback URL is embedded in live payloads.",
          "Stop the listener with stop_callback_listener when done.",
        ],
        truncated: false,
      };
    },
  });
}

export function stopCallbackListener(ctx: ToolContext) {
  return tool({
    description: `Stop an owned callback listener and return its final evidence.

Stopping touches only this listener's own job and works even after the run abort signal has fired (owned-resource cleanup). When the job record is already gone, the persisted evidence snapshot is returned instead — nothing is restarted.`,
    inputSchema: z.object({
      jobId: callbackListenerJobIdSchema,
      toolCallDescription: z
        .string()
        .describe("A concise description of this stop"),
    }),
    execute: async ({ jobId }) => {
      const handle = ctx.callbackListeners?.get(jobId);
      if (!handle) return unknownListenerResult(jobId);

      const stopReport = await stopListenerReporting(handle);
      if (stopReport.startsWith("stop failed")) {
        return failureResult(
          `Listener ${jobId} stop failed: ${stopReport.slice("stop failed: ".length)}`,
        );
      }

      // One final read after the stop settles, for hits that raced the kill.
      // A failed read never fabricates empty evidence: surface it and keep
      // the prior snapshot untouched.
      const after = await readListenerLog(
        { ...ctx, abortSignal: undefined },
        handle,
      );
      if (!after.ok) {
        return {
          success: true,
          summary: `Listener ${jobId} ${stopReport}. Final evidence could not be re-read: ${after.summary} Prior snapshot, if any, is preserved.`,
          data: {
            jobId,
            nonce: handle.nonce,
            callbackUrl: callbackUrlFor(handle) ?? null,
          },
          artifactPaths: handle.artifactPath ? [handle.artifactPath] : [],
          nextActions: [
            "Read the job log artifact directly if evidence is needed.",
          ],
          truncated: false,
        };
      }
      const status =
        after.record?.status ?? (after.gone ? "record-gone" : "stopped");
      const artifactPath = await persistEvidenceSnapshot({
        ctx,
        handle,
        status,
        evidence: after.evidence,
        logTruncated: after.logTruncated,
      });
      const summary = summarizeEvidence(after.evidence);
      return {
        success: true,
        summary: `Listener ${jobId} ${stopReport}: ${summary.callbackHits} nonce-correlated callback${summary.callbackHits === 1 ? "" : "s"}, ${summary.unrelatedHits} unrelated request${summary.unrelatedHits === 1 ? "" : "s"}.${artifactPath ? " Final evidence persisted." : " Evidence snapshot could not be persisted (inline summary only)."}`,
        data: {
          jobId,
          status,
          nonce: handle.nonce,
          callbackUrl: callbackUrlFor(handle) ?? null,
          ...summary,
          ...(after.logTruncated
            ? {
                logWindowTruncated: true,
                note: "Counts cover the visible tail of the bounded job log (lower bounds).",
              }
            : {}),
        },
        artifactPaths: artifactPath ? [artifactPath] : [],
        nextActions: [
          "Start a fresh listener if more callback evidence is needed.",
        ],
        truncated: false,
      };
    },
  });
}
