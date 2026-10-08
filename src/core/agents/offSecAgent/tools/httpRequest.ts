import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { resolveEffectiveHeaders } from "../../../http/targetHeaders";
import {
  EMPTY_PROMPT_INJECTION_LIBRARY,
  getPromptInjectionLibrary,
  type PromptInjectionLibrary,
  type PromptInjectionRef,
  redactPromptInjectionPayloads,
  resolvePromptInjectionRefs,
} from "../../../prompt-injections";
import { resolveBackends } from "../../../tools/backends/resolve";
import type { HttpResponse } from "../../../tools/backends/types";
import { agentLogsDir } from "./agentScratch";
import { assertHttpActionAllowed } from "./destructiveGuard";
import {
  assertUrlInScope,
  resolverSessionFromCtx,
  ScopeViolationError,
} from "./scopeGuard";
import type { ToolContext } from "./types";

const MAX_INLINE_BODY = 5_000;

/** Deadline applied when the model omits every timeout spelling. */
export const DEFAULT_HTTP_TIMEOUT_MS = 10_000;

export type HttpRequestTimeoutInputResolution =
  | { ok: true; ms: number | undefined }
  | { ok: false; error: string };

/**
 * `timeoutMs` (canonical) and `timeout` (legacy) are one milliseconds field.
 * Null is inactive — strict-mode models emit it for unset fields — and the
 * default applies only after alias resolution. Equal aliases pass; a
 * disagreement is rejected, never guessed or clamped.
 */
export function resolveHttpRequestTimeoutInput(input: {
  timeoutMs?: number | null;
  timeout?: number | null;
}): HttpRequestTimeoutInputResolution {
  const canonical =
    typeof input.timeoutMs === "number" ? input.timeoutMs : undefined;
  const legacy = typeof input.timeout === "number" ? input.timeout : undefined;
  if (
    canonical !== undefined &&
    legacy !== undefined &&
    !Object.is(canonical, legacy)
  ) {
    return {
      ok: false,
      error: `Conflicting timeout values: timeoutMs=${canonical} and timeout=${legacy} — both are milliseconds; pass matching values or a single field`,
    };
  }
  return { ok: true, ms: canonical ?? legacy };
}

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
  timeoutMs: z
    .number()
    .nullable()
    .optional()
    .describe(
      `Request timeout in milliseconds. Defaults to ${DEFAULT_HTTP_TIMEOUT_MS}ms when unset or null.`,
    ),
  timeout: z
    .number()
    .nullable()
    .optional()
    .describe(
      "Legacy alias for timeoutMs — same milliseconds value. Prefer timeoutMs; if both are set they must match.",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Testing SQL injection on login endpoint')",
    ),
});

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
  const inspection = ctx.sandbox
    ? "This retained artifact is on the Apex host. For evidence readable by sandbox file tools, save it with execute_command inside your file workspace."
    : ctx.fileWorkspaceRoot
      ? "This retained artifact is outside your native file workspace. Use execute_command to inspect it, or save subsequent evidence inside your file workspace."
      : "Use read_file or grep to analyze.";
  return {
    text: `${body.substring(0, MAX_INLINE_BODY)}...\n\n(truncated — ${savedNote}). ${inspection}`,
    file: filePath,
  };
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
full body. For larger evidence, use execute_command to save it inside your
file workspace (e.g. curl -o file), then page it with read_file byte windows.
When a sandbox is configured, command execution and native file tools both
operate there. Retained HTTP artifacts are stored on the Apex host; their
location is separate from files created by a sandbox command.

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
      timeoutMs,
      timeout,
    }): Promise<HttpResponse> => {
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

      // Pre-dispatch alias resolution: conflicts fail before anything is
      // requested, and the default applies only after the aliases resolve.
      const resolvedTimeout = resolveHttpRequestTimeoutInput({
        timeoutMs,
        timeout,
      });
      if (!resolvedTimeout.ok) {
        return notSent(resolvedTimeout.error);
      }
      const effectiveTimeoutMs = resolvedTimeout.ms ?? DEFAULT_HTTP_TIMEOUT_MS;

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

      {
        const response = await resolveBackends(ctx).http.request(
          { url, method, headers, body: resolvedBody, followRedirects },
          { timeoutMs: effectiveTimeoutMs, abortSignal: ctx.abortSignal },
        );
        return formatHttpResponse(response, ctx, library);
      }
    },
  });
}

function formatHttpResponse<T extends HttpResponse>(
  response: T,
  ctx: ToolContext,
  library: PromptInjectionLibrary,
): T {
  const body = redactPromptInjectionPayloads(response.body, library);
  const capture = response.capture;
  const incompleteNote =
    capture && !capture.complete
      ? `${response.error ?? capture.stopReason} (captured ${capture.capturedBytes} bytes${capture.declaredBytes !== undefined ? `; advertised Content-Length: ${capture.declaredBytes}` : ""})`
      : undefined;
  return {
    ...response,
    body: maybeSaveBody(body, ctx, { incompleteNote }).text,
    headers: Object.fromEntries(
      Object.entries(response.headers).map(([key, value]) => [
        key,
        redactPromptInjectionPayloads(value, library),
      ]),
    ),
    ...(response.error
      ? { error: redactPromptInjectionPayloads(response.error, library) }
      : {}),
  };
}
