import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import {
  resolveEffectiveHeaders,
  shellQuote,
  targetFetch,
} from "../../../http/targetHeaders";
import {
  EMPTY_PROMPT_INJECTION_LIBRARY,
  getPromptInjectionLibrary,
  type PromptInjectionLibrary,
  type PromptInjectionRef,
  redactPromptInjectionPayloads,
  resolvePromptInjectionRefs,
} from "../../../prompt-injections";
import { agentLogsDir } from "./agentScratch";
import { assertHttpActionAllowed } from "./destructiveGuard";
import {
  assertUrlInScope,
  resolverSessionFromCtx,
  ScopeViolationError,
} from "./scopeGuard";
import type { ToolContext } from "./types";
import { buildWindowsCurlCommand } from "./windowsCurl";

const MAX_INLINE_BODY = 5_000;
// Cap on bytes buffered/decoded — response.text() buffers the whole body
// before truncating, so a stalling or endless body must be bounded at capture.
const MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024;

/** Why the body capture ended. `end` is the only complete outcome. */
export type BodyCaptureStopReason =
  | "end"
  | "byte-cap"
  | "timeout"
  | "aborted"
  | "error"
  | "curl-exit"
  | "sandbox-exec";

export type HttpRequestResult = {
  /**
   * True only when the transfer completed AND the status is 2xx/3xx. A capped
   * or interrupted capture is never an ordinary success — see `capture`.
   */
  success: boolean;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  url: string;
  redirected: boolean;
  error?: string;
  method?: string;
  /** Structured producer-capture outcome; the inline body is only a preview. */
  capture: {
    complete: boolean;
    stopReason: BodyCaptureStopReason;
    /**
     * `raw` counts undecoded body bytes on the local path. `decoded` counts
     * the UTF-8 length of the sandbox body text, after decoding; replacement
     * characters can make this larger than the raw capture limit.
     */
    capturedBytes: number;
    capturedBytesBasis: "raw" | "decoded";
    /**
     * Advertised Content-Length, when the response carried one. With
     * auto-decompression this is the ENCODED length — it is not a denominator
     * for capturedBytes.
     */
    declaredBytes?: number;
  };
};

const promptInjectionRefSchema = z.object({
  kind: z.literal("prompt_injection_ref"),
  id: z
    .string()
    .describe("Stable prompt-injection id returned by list_prompt_injections"),
});

const httpRequestInputSchema = z.object({
  url: z.string().describe("The URL to request"),
  method: z
    .enum(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
    .default("GET"),
  headers: z
    .string()
    .optional()
    .describe(
      'HTTP headers as a JSON-encoded object string, e.g. \'{"Content-Type": "application/json", "Authorization": "Bearer token"}\'',
    ),
  body: z
    .union([z.string(), promptInjectionRefSchema])
    .optional()
    .describe(
      "Request body (for POST, PUT, PATCH). To use a hidden prompt-injection payload, pass a PromptInjectionRef object instead of raw payload text.",
    ),
  followRedirects: z
    .boolean()
    .default(false)
    .describe(
      "Whether to follow HTTP redirects (3xx). Defaults to false so you can see redirect responses with Location and Set-Cookie headers.",
    ),
  timeout: z.number().default(10000),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Testing SQL injection on login endpoint')",
    ),
});

type HttpRequestInput = z.infer<typeof httpRequestInputSchema>;

type HttpRequestBody = string | PromptInjectionRef | undefined;

/**
 * Check if a value contains any PromptInjectionRef (recursively).
 */
function containsPromptInjectionRef(value: unknown): boolean {
  if (
    typeof value === "object" &&
    value !== null &&
    (value as Record<string, unknown>).kind === "prompt_injection_ref"
  ) {
    return true;
  }

  if (Array.isArray(value)) {
    return value.some((item) => containsPromptInjectionRef(item));
  }

  if (typeof value === "object" && value !== null) {
    return Object.values(value).some((nested) =>
      containsPromptInjectionRef(nested),
    );
  }

  return false;
}

/**
 * If `body` exceeds the inline limit, save the full text to a file under
 * this agent's log dir (`http-responses/`) and return truncated text + file
 * path. Scoped per-subagent via {@link agentLogsDir} so a host can reclaim a
 * finished subagent's response dumps mid-scan. An `incompleteNote` marks a
 * known-partial capture — the inline text never claims a full response was
 * saved when it wasn't.
 */
function maybeSaveBody(
  body: string,
  ctx: ToolContext,
  opts?: { incompleteNote?: string },
): { text: string; file?: string } {
  const incomplete = opts?.incompleteNote;

  if (body.length <= MAX_INLINE_BODY) {
    return {
      text: incomplete ? `${body}\n\n(INCOMPLETE — ${incomplete})` : body,
    };
  }

  const outputDir = join(agentLogsDir(ctx), "http-responses");
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `response-${ts}.txt`;
  const filePath = join(outputDir, filename);

  try {
    writeFileSync(filePath, body);
  } catch {
    const failedNote = incomplete
      ? `INCOMPLETE — ${incomplete}; failed to save partial response to file`
      : "failed to save full response to file";
    return {
      text: `${body.substring(0, MAX_INLINE_BODY)}...\n\n(truncated — ${failedNote})`,
    };
  }

  const savedNote = incomplete
    ? `INCOMPLETE — ${incomplete}; partial response saved to ${filePath}`
    : `full response saved to ${filePath}`;
  return {
    text: `${body.substring(0, MAX_INLINE_BODY)}...\n\n(truncated — ${savedNote}). Use read_file or grep to analyze.`,
    file: filePath,
  };
}

/**
 * Reads up to `maxBytes` into one owned buffer (per-chunk arrays are not a
 * memory bound), cancelling the reader past the cap. Never awaits `cancel()`
 * (it may never settle). A mid-read abort or stream error returns the partial
 * capture plus a stop reason — the caller keeps status/headers and the
 * bounded partial body instead of discarding them.
 */
type CappedBodyRead = {
  text: string;
  received: number;
  stopReason: "end" | "byte-cap" | "aborted" | "error";
  cause?: unknown;
};

async function readBodyCapped(
  response: Response,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<CappedBodyRead> {
  const captured = (): CappedBodyRead => ({
    text: new TextDecoder().decode(buf.subarray(0, received)),
    received,
    stopReason,
    cause,
  });
  // Assigned by the loop below; the closures above read them after it exits.
  let buf = new Uint8Array(0);
  let received = 0;
  let stopReason: CappedBodyRead["stopReason"] = "end";
  let cause: unknown;

  if (signal?.aborted) {
    response.body?.cancel().catch(() => {});
    stopReason = "aborted";
    return captured();
  }
  const body = response.body;
  if (!body) return { text: "", received: 0, stopReason: "end" };

  const reader = body.getReader();
  // Native-stream arbiter: ONE race, created before the first read. The abort
  // listener resolves the sentinel BEFORE cancelling, and reader.closed
  // stays raw inside the race — a reaction hop would reorder same-turn
  // events. Whichever settles first is the terminal outcome.
  let onAbort: (() => void) | undefined;
  const aborted = signal
    ? new Promise<"aborted">((resolve) => {
        onAbort = () => {
          resolve("aborted");
          reader.cancel().catch(() => {});
        };
        signal.addEventListener("abort", onAbort, { once: true });
      })
    : null;
  const ended = (
    aborted ? Promise.race([reader.closed, aborted]) : reader.closed
  ).then<
    { kind: "end" } | { kind: "aborted" },
    { kind: "error"; cause: unknown }
  >(
    (result) => ({ kind: result === "aborted" ? "aborted" : "end" }),
    (error) => ({ kind: "error", cause: error }),
  );

  buf = new Uint8Array(Math.min(maxBytes, 64 * 1024));

  const append = (value: Uint8Array, take: number) => {
    if (take <= 0) return;
    if (received + take > buf.byteLength) {
      // Geometric growth, hard-capped at maxBytes.
      let size = buf.byteLength;
      while (size < received + take && size < maxBytes) size *= 2;
      const next = new Uint8Array(Math.min(size, maxBytes));
      next.set(buf.subarray(0, received));
      buf = next;
    }
    buf.set(value.subarray(0, take), received);
    received += take;
  };

  try {
    while (true) {
      let result: Awaited<ReturnType<typeof reader.read>>;
      try {
        result = await reader.read();
      } catch {
        // The arbiter carries the terminal cause; the read's rejection is
        // the same event seen from the read side. Processing failures below
        // propagate through the finally — they are not stream outcomes.
        break;
      }
      const { done, value } = result;
      if (done) break;
      if (!value?.byteLength) continue;
      const room = maxBytes - received;
      if (value.byteLength > room) {
        append(value, room);
        stopReason = "byte-cap";
        reader.cancel().catch(() => {});
        break;
      }
      append(value, value.byteLength);
      // At the exact cap, keep reading until EOF or a nonempty overflow chunk.
    }
  } finally {
    if (onAbort) signal?.removeEventListener("abort", onAbort);
    // Cancel before release: a processing exception escaping the loop must
    // not leave the stream merely released while the producer keeps pulling.
    reader.cancel().catch(() => {});
    try {
      reader.releaseLock();
    } catch {
      // cancel()/read failure may have already released the lock
    }
  }

  // Cap is explicit and final — never awaited or overwritten by the arbiter.
  if (stopReason === "byte-cap") return captured();

  const end = await ended;
  if (end.kind === "aborted") {
    stopReason = "aborted";
  } else if (end.kind === "error") {
    // Identity, not name: native fetch cancellation rejects the body with
    // the signal's own reason object; an unrelated AbortError-shaped error
    // from an adapter stays an error even once the host signal aborts.
    cause = end.cause;
    stopReason =
      signal?.aborted && end.cause === signal.reason ? "aborted" : "error";
  }
  return captured();
}

function parseHeaders(raw: string | undefined): Record<string, string> {
  if (!raw) return {};
  if (typeof raw === "object") return raw as unknown as Record<string, string>;
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed))
      return parsed as Record<string, string>;
  } catch {
    // ignore
  }
  return {};
}

export function httpRequest(ctx: ToolContext) {
  return tool({
    description: `Make HTTP requests with detailed response analysis for web application testing.

USAGE GUIDANCE:
- Always check response headers for security misconfigurations
- Look for: X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, Permissions-Policy, Cross-Origin-Embedder-Policy, Cross-Origin-Opener-Policy (NOTE: X-XSS-Protection is deprecated by all major browsers — do NOT recommend it; recommend Content-Security-Policy instead)
- Analyze cookies for HttpOnly, Secure, SameSite flags
- Check for verbose error messages that leak information
- Test for common web vulnerabilities (SQL injection, XSS, IDOR)
- Monitor response times for blind injection attacks
- Test different HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS)

CORS TESTING (per Fetch specification browser enforcement rules):
- Access-Control-Allow-Origin: * with NO credentials flag = any site can read non-authenticated responses. Usually LOW impact unless the response itself contains sensitive data.
- Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true = BROWSERS BLOCK THIS per the Fetch spec. The headers contradict each other. This is a server misconfiguration but NOT exploitable as a credential-stealing CORS bypass. Severity: LOW (misconfiguration only).
- Reflected Origin + Access-Control-Allow-Credentials: true = ACTUAL HIGH SEVERITY. The server echoes back whatever Origin the attacker sends, allowing any site to make credentialed cross-origin requests. To test: send a request with header "Origin: https://evil.example.com" and check if Access-Control-Allow-Origin in the response reflects that exact value.
- Access-Control-Allow-Origin: null + Access-Control-Allow-Credentials: true = exploitable from sandboxed iframes (data: URIs, sandboxed frames). Severity: MEDIUM-HIGH.
- ALWAYS actively test for origin reflection: send an OPTIONS or GET request with "Origin: https://evil.example.com" header and inspect whether Access-Control-Allow-Origin echoes it back. This is the most dangerous CORS pattern.
- IMPORTANT: CORS is only relevant for endpoints that use cookie-based or token-based authentication. If the endpoint requires NO authentication at all, CORS configuration does not change the risk — the endpoint is directly callable from any client regardless of CORS headers. Do not document CORS misconfigurations on unauthenticated endpoints.

RESPONSES ARE BOUNDED: bodies larger than 5 MiB are capped and marked
INCOMPLETE — the saved partial file holds only the captured prefix, not the
full body. For larger evidence, save it to a file and inspect bounded ranges:
locally, redirect with execute_command (e.g. curl -o file) and page it with
read_file byte windows; in a sandbox, execute_command runs remotely, so save
AND inspect there (e.g. curl -o file, then head/dd on the file) — read_file
only reads host-local files.

COMMON TESTING PATTERNS:
- Test with/without authentication
- Try different user agents
- Check for API endpoints (/api/, /v1/, /graphql)
- Look for admin panels (/admin, /administrator, /wp-admin)
- Test for backup files (.bak, .old, ~, .swp)`,
    inputSchema: httpRequestInputSchema,
    execute: async ({
      url,
      method,
      headers: rawHeaders,
      body,
      followRedirects,
      timeout,
    }): Promise<HttpRequestResult> => {
      let headers = parseHeaders(rawHeaders);

      // Pre-dispatch failures: nothing was requested, so nothing was captured.
      const notSent = (
        error: string,
        stopReason: BodyCaptureStopReason = "error",
      ): HttpRequestResult => ({
        success: false,
        error,
        url,
        method,
        status: 0,
        statusText: "",
        headers: {},
        body: "",
        redirected: false,
        capture: {
          complete: false,
          stopReason,
          capturedBytes: 0,
          capturedBytesBasis: "raw",
        },
      });

      try {
        assertUrlInScope(url, ctx);
      } catch (e) {
        if (e instanceof ScopeViolationError) {
          return notSent(e.message);
        }
        throw e;
      }

      let resolvedBody: string | undefined;
      let library: PromptInjectionLibrary = EMPTY_PROMPT_INJECTION_LIBRARY;

      try {
        // Check if we need to load the library (only if there are prompt injection refs)
        const needsLibrary =
          containsPromptInjectionRef(body) ||
          containsPromptInjectionRef(headers);
        library = needsLibrary
          ? await getPromptInjectionLibrary({
              library: ctx.promptInjectionLibrary,
              source: ctx.promptInjectionLibrarySource,
            })
          : EMPTY_PROMPT_INJECTION_LIBRARY;

        headers = resolvePromptInjectionRefs(headers, library);
        resolvedBody =
          body === undefined
            ? undefined
            : String(
                resolvePromptInjectionRefs(body as HttpRequestBody, library),
              );

        // Enforce the destructive-action guard on the fully resolved body and
        // the EFFECTIVE headers (agent-supplied + session/credential headers
        // merged in) — a prompt-injection ref expands to a concrete string only
        // here, and a method-override header can be injected by the session
        // layer, so classifying before this point (or on agent headers alone)
        // would miss those.
        const effectiveHeaders = resolveEffectiveHeaders(
          resolverSessionFromCtx(ctx),
          url,
          headers,
        );
        assertHttpActionAllowed(
          { method, url, body: resolvedBody, headers: effectiveHeaders },
          ctx,
        );
      } catch (e) {
        return notSent(e instanceof Error ? e.message : String(e));
      }

      // Rate-limit chokepoint for both dispatch paths (no-op when unset).
      const slotAcquired =
        (await ctx.session._rateLimiter?.acquireSlot(ctx.abortSignal)) ?? false;
      if (ctx.abortSignal?.aborted) {
        if (slotAcquired) ctx.session._rateLimiter?.releaseSlot();
        return notSent("Request aborted by user", "aborted");
      }

      // Sandbox mode: build a curl command and run it inside the sandbox
      if (ctx.sandbox) {
        return executeSandboxHttpRequest(
          ctx,
          {
            url,
            method,
            headers,
            body: resolvedBody,
            followRedirects,
            timeout,
          },
          library,
        );
      }

      // Local mode: use native fetch
      let timeoutId: ReturnType<typeof setTimeout> | undefined;

      try {
        const timeoutController = new AbortController();
        timeoutId = setTimeout(() => timeoutController.abort(), timeout);

        const combinedSignal = ctx.abortSignal
          ? AbortSignal.any([ctx.abortSignal, timeoutController.signal])
          : timeoutController.signal;

        const response = await targetFetch(resolverSessionFromCtx(ctx), url, {
          method,
          headers,
          body: resolvedBody || undefined,
          redirect: followRedirects ? "follow" : "manual",
          signal: combinedSignal,
        });

        const responseHeaders: Record<string, string> = {};
        response.headers.forEach((value, key) => {
          responseHeaders[key] = value;
        });

        // Deadline covers headers AND body — clearing it at the headers leaves the read unbounded (see readBodyCapped).
        const read = await readBodyCapped(
          response,
          MAX_DOWNLOAD_BYTES,
          combinedSignal,
        );
        // The combined signal cannot say which source fired; the host signal
        // decides between user abort and deadline.
        const stopReason: BodyCaptureStopReason =
          read.stopReason === "aborted"
            ? ctx.abortSignal?.aborted
              ? "aborted"
              : "timeout"
            : read.stopReason;
        const complete = stopReason === "end";
        const declaredRaw = response.headers.get("content-length");
        const declared = declaredRaw ? Number.parseInt(declaredRaw, 10) : NaN;
        const declaredBytes =
          Number.isSafeInteger(declared) && declared >= 0
            ? declared
            : undefined;
        const incompleteError =
          stopReason === "timeout"
            ? `Request timeout after ${timeout}ms — partial body captured`
            : stopReason === "aborted"
              ? "Request aborted by user — partial body captured"
              : stopReason === "byte-cap"
                ? `download capped at ${MAX_DOWNLOAD_BYTES} bytes — for larger evidence, save it with execute_command (curl -o file) and page it with read_file byte windows`
                : read.cause instanceof Error
                  ? read.cause.message
                  : String(read.cause);

        const redactedBody = redactPromptInjectionPayloads(read.text, library);
        const redactedHeaders = Object.fromEntries(
          Object.entries(responseHeaders).map(([key, value]) => [
            key,
            redactPromptInjectionPayloads(value, library),
          ]),
        );
        // Advertised length is labeled, never a denominator: content-encoding
        // decompression makes encoded Content-Length and captured bytes
        // incomparable.
        const { text: truncatedBody } = maybeSaveBody(redactedBody, ctx, {
          incompleteNote: complete
            ? undefined
            : `${incompleteError} (captured ${read.received} bytes${
                declaredBytes !== undefined
                  ? `; advertised Content-Length: ${declaredBytes}`
                  : ""
              })`,
        });

        return {
          // Complete capture — including a complete 4xx/5xx, which keeps the
          // pre-existing local-path semantics (the sandbox path has always
          // gated on status; that asymmetry predates this change).
          success: complete,
          error: complete ? undefined : incompleteError,
          status: response.status,
          statusText: response.statusText,
          headers: redactedHeaders,
          body: truncatedBody,
          url: response.url,
          redirected: response.redirected,
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
        const errorMsg = isAbort
          ? ctx.abortSignal?.aborted
            ? "Request aborted by user"
            : `Request timeout after ${timeout}ms`
          : error instanceof Error
            ? error.message
            : String(error);

        // The fetch itself failed — no headers or body ever arrived.
        return {
          success: false,
          error: errorMsg,
          url,
          method,
          status: 0,
          statusText: "",
          headers: {},
          body: "",
          redirected: false,
          capture: {
            complete: false,
            stopReason: isAbort
              ? ctx.abortSignal?.aborted
                ? "aborted"
                : "timeout"
              : "error",
            capturedBytes: 0,
            capturedBytesBasis: "raw",
          },
        };
      } finally {
        if (timeoutId) clearTimeout(timeoutId);
      }
    },
  });
}

// ---------------------------------------------------------------------------
// Sandbox HTTP helper (curl-based)
// ---------------------------------------------------------------------------

async function executeSandboxHttpRequest(
  ctx: ToolContext,
  opts: {
    url: string;
    method: string;
    headers?: Record<string, string>;
    body?: string;
    followRedirects: boolean;
    timeout: number;
  },
  library: PromptInjectionLibrary,
): Promise<HttpRequestResult> {
  const { url, method, headers, body, followRedirects, timeout } = opts;

  const { sandbox } = ctx;
  if (!sandbox) {
    throw new Error("executeSandboxHttpRequest requires a sandbox");
  }

  // Hoisted so the `finally` can delete the request-body temp file on every
  // path — otherwise every POST/PUT/PATCH leaves a `/tmp/apex_http_body_*`
  // file behind for the life of the sandbox, and a body-heavy scan can fill
  // the disk (ENOSPC).
  let bodyTempFile: string | null = null;

  try {
    // Resolve session/credential headers so the sandbox curl path matches
    // the local fetch path. Caller `headers` win as the request layer.
    const mergedHeaders = resolveEffectiveHeaders(
      resolverSessionFromCtx(ctx),
      url,
      headers,
    );

    const timeoutSeconds = Math.ceil(timeout / 1000);
    const nonce = randomBytes(8).toString("hex");
    const exitMarker = `__APEX_${nonce}_CURL_EXIT_`;
    // Windows: +15s headroom — 5s PowerShell startup, 5s EOF/drain process-exit
    // grace, 5s kill confirmation — before the adapter tears the call down.
    // Linux keeps the existing floor.
    const executeOpts: {
      timeout: number;
      envVars?: Record<string, string>;
    } = {
      timeout:
        sandbox.type === "windows"
          ? Math.max(timeoutSeconds + 15, 30)
          : Math.max(timeoutSeconds, 30),
    };

    let command: string;
    if (sandbox.type === "windows") {
      // Windows helper: fixed encoded script; request data (CRT-quoted argv,
      // base64 body, marker, byte cap) travels in envVars. No POSIX printf
      // /tmp body staging and no rm cleanup on this path.
      const win = buildWindowsCurlCommand({
        url,
        method,
        headers: mergedHeaders,
        body:
          body && ["POST", "PUT", "PATCH"].includes(method) ? body : undefined,
        followRedirects,
        timeoutSeconds,
        maxBytes: MAX_DOWNLOAD_BYTES,
        exitMarker,
      });
      command = win.command;
      executeOpts.envVars = win.envVars;
    } else {
      let curlCommand = `curl -sS -i -X ${method}`;
      for (const [key, value] of Object.entries(mergedHeaders)) {
        curlCommand += ` -H "${shellQuote(`${key}: ${value}`)}"`;
      }

      // If we have a body to send, write it to a temp file in the sandbox
      // to avoid shell escaping issues with multiline content
      if (body && ["POST", "PUT", "PATCH"].includes(method)) {
        bodyTempFile = `/tmp/apex_http_body_${Date.now()}_${Math.random().toString(36).slice(2, 11)}.txt`;

        // Use printf to safely write the body to the temp file
        const escapedForPrintf = body
          .replace(/\\/g, "\\\\")
          .replace(/%/g, "%%");
        const writeCommand = `printf '%s' '${escapedForPrintf.replace(/'/g, "'\\''")}' > ${bodyTempFile}`;

        const writeResult = await sandbox.execute(writeCommand, {
          timeout: 30,
        });
        if (!writeResult.success || writeResult.exitCode !== 0) {
          return {
            success: false,
            error: `Failed to write request body to sandbox temp file: ${writeResult.stderr || writeResult.stdout}`,
            url,
            method,
            status: 0,
            statusText: "",
            headers: {},
            body: "",
            redirected: false,
            capture: {
              complete: false,
              stopReason: "error",
              capturedBytes: 0,
              capturedBytesBasis: "raw",
            },
          };
        }

        curlCommand += ` --data-binary @${bodyTempFile}`;
      }

      if (followRedirects) {
        curlCommand += " -L";
      }

      curlCommand += ` --max-time ${timeoutSeconds}`;
      curlCommand += ` "${url}"`;

      // Reserve metadata space so a completed exact-cap response keeps its
      // exit marker. Any response bytes using that reserve are clipped below.
      // Base64 preserves raw bytes through the adapter's text-only stdout.
      const markerBytes = Buffer.byteLength(`\n${exitMarker}255\n`);
      command = `( ${curlCommand}; printf '\\n${exitMarker}%s\\n' "$?" ) 2>&1 | head -c ${MAX_DOWNLOAD_BYTES + markerBytes} | base64`;
    }

    const result = await sandbox.execute(command, executeOpts);

    const rawOutput =
      sandbox.type === "windows"
        ? undefined
        : Buffer.from(result.stdout || "", "base64");
    const output = rawOutput?.toString("utf8") ?? result.stdout ?? "";
    // Marker absent = head cut the stream at the cap (curl SIGPIPE'd before
    // writing it) or the pipeline was killed — either way incomplete. The
    // random nonce keeps a hostile body from forging a clean exit. Windows
    // native termination can be negative, so the exit is parsed signed.
    const markerMatch = output.match(
      new RegExp(`\\n?${exitMarker}(-?\\d+)\\n?$`),
    );
    const curlExit = markerMatch ? parseInt(markerMatch[1], 10) : null;
    const unmarkedOutput =
      markerMatch !== null ? output.slice(0, markerMatch.index) : output;
    const responseBytes = rawOutput
      ? rawOutput.length - (markerMatch ? Buffer.byteLength(markerMatch[0]) : 0)
      : 0;
    const captureOverflow =
      rawOutput !== undefined && responseBytes > MAX_DOWNLOAD_BYTES;
    const boundedOutput = rawOutput
      ? rawOutput
          .subarray(0, Math.min(responseBytes, MAX_DOWNLOAD_BYTES))
          .toString("utf8")
      : unmarkedOutput;

    // Headers tolerate spec CRLF; the body is sliced raw from the original
    // output — splitting the whole stream would normalize its line endings
    // and corrupt evidence.
    let statusLine = "";
    const responseHeaders: Record<string, string> = {};
    let bodyStart = -1;
    let headerStart = 0;

    const statusLineMatch = boundedOutput.match(/(?:^|\r?\n)(HTTP\/[^\r\n]*)/);
    if (statusLineMatch?.index !== undefined) {
      statusLine = statusLineMatch[1];
      headerStart = statusLineMatch.index + statusLineMatch[0].length;
      const sepMatch = boundedOutput.slice(headerStart).match(/\r?\n\r?\n/);
      if (sepMatch?.index !== undefined) {
        const headerBlock = boundedOutput.slice(
          headerStart,
          headerStart + sepMatch.index,
        );
        for (const line of headerBlock.split(/\r?\n/)) {
          if (line.trim() === "") continue;
          const headerMatch = line.match(/^([^:]+):\s*(.+)$/);
          if (headerMatch) {
            responseHeaders[headerMatch[1].toLowerCase()] = headerMatch[2];
          }
        }
        bodyStart = headerStart + sepMatch.index + sepMatch[0].length;
      }
    }

    const statusMatch = statusLine.match(/HTTP\/[\d.]+\s+(\d+)\s+(.+)/);
    const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
    const statusText = statusMatch ? statusMatch[2] : "Unknown";
    // No HTTP line at all → the transport noise/error text is the body
    // evidence; a status line without a blank separator keeps the raw
    // remainder after it.
    const responseBody =
      bodyStart >= 0
        ? boundedOutput.slice(bodyStart)
        : boundedOutput.slice(headerStart);

    const redactedBody = redactPromptInjectionPayloads(responseBody, library);
    const redactedHeaders = Object.fromEntries(
      Object.entries(responseHeaders).map(([key, value]) => [
        key,
        redactPromptInjectionPayloads(value, library),
      ]),
    );

    // Transport outcome comes from curl's exit, not the parsed status line —
    // a --max-time cutoff (exit 28) still writes "HTTP/1.1 200" plus a
    // partial body. Partial status/headers/body are returned as evidence.
    const sandboxTransportOk = result.success && result.exitCode === 0;
    const transferComplete =
      sandboxTransportOk && curlExit === 0 && !captureOverflow;
    const stopReason: BodyCaptureStopReason = !sandboxTransportOk
      ? "sandbox-exec"
      : captureOverflow || curlExit == null
        ? "byte-cap"
        : curlExit !== 0
          ? "curl-exit"
          : "end";
    const capturedBytes = Buffer.byteLength(responseBody, "utf-8");
    const declaredRaw = responseHeaders["content-length"];
    const declared = declaredRaw ? Number.parseInt(declaredRaw, 10) : NaN;
    const declaredBytes =
      Number.isSafeInteger(declared) && declared >= 0 ? declared : undefined;
    // Native curl/helper errors surface via sandbox stderr — include them in
    // the failure diagnostics instead of suppressing them.
    const redactedSandboxStderr = redactPromptInjectionPayloads(
      result.stderr || "",
      library,
    );
    const incompleteNote = !sandboxTransportOk
      ? `sandbox execution failed (exit ${result.exitCode})${redactedSandboxStderr ? `: ${redactedSandboxStderr}` : ""}; output may be partial`
      : captureOverflow || curlExit == null
        ? `output capped at ${MAX_DOWNLOAD_BYTES} bytes; ${curlExit == null ? "curl exit unknown" : `curl exited ${curlExit}`} — for larger evidence, save and inspect it inside the sandbox with execute_command (curl -o file, then head/dd on the file); read_file only reads host-local files`
        : curlExit !== 0
          ? `curl exited ${curlExit}${redactedSandboxStderr ? `: ${redactedSandboxStderr}` : ""}; output may be partial`
          : undefined;

    const { text: truncatedBody } = maybeSaveBody(redactedBody, ctx, {
      incompleteNote,
    });

    return {
      success: transferComplete && status >= 200 && status < 400,
      error: incompleteNote,
      status,
      statusText,
      headers: redactedHeaders,
      body: truncatedBody,
      url,
      redirected: false,
      capture: {
        complete: transferComplete,
        stopReason,
        capturedBytes,
        capturedBytesBasis: "decoded",
        ...(declaredBytes !== undefined ? { declaredBytes } : {}),
      },
    };
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      error: msg,
      status: 0,
      statusText: "Error",
      headers: {},
      body: "",
      url,
      redirected: false,
      capture: {
        complete: false,
        stopReason: "error",
        capturedBytes: 0,
        capturedBytesBasis: "raw",
      },
    };
  } finally {
    // Reclaim the request-body temp file now that curl has read it. Best-effort
    // — a failed cleanup must not change the request result.
    if (bodyTempFile) {
      await sandbox
        .execute(`rm -f ${bodyTempFile}`, { timeout: 10 })
        .catch(() => {});
    }
  }
}
