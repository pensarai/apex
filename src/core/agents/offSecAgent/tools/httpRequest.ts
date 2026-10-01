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
import { resolveBackends } from "../../../tools/backends";
import type { HttpRequest } from "../../../tools/backends/types";
import { agentLogsDir } from "./agentScratch";
import { assertHttpActionAllowed } from "./destructiveGuard";
import {
  assertUrlInScope,
  resolverSessionFromCtx,
  ScopeViolationError,
} from "./scopeGuard";
import type { ToolContext } from "./types";

const MAX_INLINE_BODY = 5_000;

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
  extract: z
    .enum(["readability"])
    .optional()
    .describe(
      "Set to 'readability' to fetch a GET page and extract its title and main text content instead of the raw response — the same behavior as get_page. Ignores method/headers/body and is not scope- or destructive-action-checked; use it for CVE writeups, vendor docs and other research URLs.",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Testing SQL injection on login endpoint')",
    ),
});

type HttpRequestInput = z.infer<typeof httpRequestInputSchema>;

export type HttpRequestResult = {
  success: boolean;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  url: string;
  redirected: boolean;
  error?: string;
  method?: string;
  title?: string;
};

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
 * finished subagent's response dumps mid-scan.
 */
function maybeSaveBody(
  body: string,
  ctx: ToolContext,
): { text: string; file?: string } {
  if (body.length <= MAX_INLINE_BODY) return { text: body };

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
    return {
      text: `${body.substring(0, MAX_INLINE_BODY)}...\n\n(truncated — failed to save full response to file)`,
    };
  }

  return {
    text: `${body.substring(0, MAX_INLINE_BODY)}...\n\n(truncated — full response saved to ${filePath}). Use read_file or grep to analyze.`,
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

function emptyResult(
  base: Partial<HttpRequestResult> & { url: string; method: string },
): HttpRequestResult {
  return {
    success: false,
    status: 0,
    statusText: "",
    headers: {},
    body: "",
    redirected: false,
    ...base,
  };
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

COMMON TESTING PATTERNS:
- Test with/without authentication
- Try different user agents
- Check for API endpoints (/api/, /v1/, /graphql)
- Look for admin panels (/admin, /administrator, /wp-admin)
- Test for backup files (.bak, .old, ~, .swp)

READABILITY EXTRACTION:
- Set extract: 'readability' to fetch a page and read its title and main text
  content instead of raw HTML — the same tool previously named get_page. Use
  this after web_search to read CVE details, security advisories and
  documentation. It is GET-only and ignores headers/body.`,
    inputSchema: httpRequestInputSchema,
    execute: async ({
      url,
      method,
      headers: rawHeaders,
      body,
      followRedirects,
      timeout,
      extract,
    }): Promise<HttpRequestResult> => {
      const backends = resolveBackends(ctx);

      if (extract === "readability") {
        const response = await backends.http.request(
          { url, extract: "readability" },
          { timeoutMs: timeout, abortSignal: ctx.abortSignal },
        );
        return { ...response, method };
      }

      let headers = parseHeaders(rawHeaders);

      try {
        assertUrlInScope(url, ctx);
      } catch (e) {
        if (e instanceof ScopeViolationError) {
          return emptyResult({ error: e.message, url, method });
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

        // Classify the fully resolved body and the effective headers (agent
        // headers merged with session/credential headers), before a rate-limit
        // slot is taken.
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
        return emptyResult({
          error: e instanceof Error ? e.message : String(e),
          url,
          method,
        });
      }

      // Rate-limit chokepoint for both dispatch paths (no-op when unset).
      const slotAcquired =
        (await ctx.session._rateLimiter?.acquireSlot(ctx.abortSignal)) ?? false;
      if (ctx.abortSignal?.aborted) {
        if (slotAcquired) ctx.session._rateLimiter?.releaseSlot();
        return emptyResult({
          error: "Request aborted by user",
          url,
          method,
        });
      }

      const request: HttpRequest = {
        url,
        method,
        headers,
        body: resolvedBody,
        followRedirects,
      };

      try {
        const response = await backends.http.request(request, {
          timeoutMs: timeout,
          abortSignal: ctx.abortSignal,
        });
        if (!response.success) {
          return { ...response, method };
        }

        const redactedBody = redactPromptInjectionPayloads(
          response.body,
          library,
        );
        const redactedHeaders = Object.fromEntries(
          Object.entries(response.headers).map(([key, value]) => [
            key,
            redactPromptInjectionPayloads(value, library),
          ]),
        );
        const { text: truncatedBody } = maybeSaveBody(redactedBody, ctx);

        return {
          success: true,
          status: response.status,
          statusText: response.statusText,
          headers: redactedHeaders,
          body: truncatedBody,
          url: response.url,
          redirected: response.redirected,
        };
      } catch (error: unknown) {
        return emptyResult({
          error: error instanceof Error ? error.message : String(error),
          url,
          method,
        });
      }
    },
  });
}
