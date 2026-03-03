import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

export const httpRequestInputSchema = z.object({
  url: z.string().describe("The URL to request"),
  method: z
    .enum(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
    .default("GET"),
  headers: z
    .preprocess((val) => {
      if (typeof val === "string") {
        try {
          return JSON.parse(val);
        } catch {
          return {};
        }
      }
      return val;
    }, z.record(z.string(), z.string()).optional())
    .describe("HTTP headers as key-value pairs (object or JSON string)"),
  body: z.string().optional().describe("Request body (for POST, PUT, PATCH)"),
  rawHeaders: z
    .array(z.tuple([z.string(), z.string()]))
    .optional()
    .describe(
      "Raw header tuples for sending duplicate headers (e.g., two Authorization headers for parser differential testing). When provided, takes precedence over `headers`.",
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

export type HttpRequestInput = z.infer<typeof httpRequestInputSchema>;

export type HttpRequestResult = {
  success: boolean;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  url: string;
  redirected: boolean;
  responseTimeMs?: number;
  error?: string;
  method?: string;
};

export function httpRequest(ctx: ToolContext) {
  return tool({
    description: `Make HTTP requests with detailed response analysis for web application testing.

USAGE GUIDANCE:
- Always check response headers for security misconfigurations
- Look for: X-Frame-Options, X-XSS-Protection, CSP, HSTS, X-Content-Type-Options
- Analyze cookies for HttpOnly, Secure, SameSite flags
- Check for verbose error messages that leak information
- Test for common web vulnerabilities (SQL injection, XSS, IDOR)
- Monitor response times for blind injection attacks (responseTimeMs in result)
- Use rawHeaders for parser differential testing (duplicate headers, e.g. two Authorization values)
- Test different HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS)

COMMON TESTING PATTERNS:
- Test with/without authentication
- Try different user agents
- Test for CORS misconfigurations
- Check for API endpoints (/api/, /v1/, /graphql)
- Look for admin panels (/admin, /administrator, /wp-admin)
- Test for backup files (.bak, .old, ~, .swp)`,
    inputSchema: httpRequestInputSchema,
    execute: async ({
      url,
      method,
      headers,
      rawHeaders,
      body,
      followRedirects,
      timeout,
    }): Promise<HttpRequestResult> => {
      // Sandbox mode: build a curl command and run it inside the sandbox
      if (ctx.sandbox) {
        return executeSandboxHttpRequest(ctx, {
          url,
          method,
          headers,
          rawHeaders,
          body,
          followRedirects,
          timeout,
        });
      }

      // Local mode: use native fetch
      let timeoutId: ReturnType<typeof setTimeout> | undefined;

      try {
        if (ctx.abortSignal?.aborted) {
          return {
            success: false,
            error: "Request aborted by user",
            url,
            method,
            status: 0,
            statusText: "",
            headers: {},
            body: "",
            redirected: false,
            responseTimeMs: 0,
          };
        }

        const timeoutController = new AbortController();
        timeoutId = setTimeout(() => timeoutController.abort(), timeout);

        const combinedSignal = ctx.abortSignal
          ? AbortSignal.any([ctx.abortSignal, timeoutController.signal])
          : timeoutController.signal;

        // Build headers — rawHeaders supports duplicates via Headers.append()
        let fetchHeaders: HeadersInit;
        if (rawHeaders) {
          const h = new Headers();
          for (const [key, value] of rawHeaders) {
            h.append(key, value);
          }
          fetchHeaders = h;
        } else {
          fetchHeaders = headers || {};
        }

        const startTime = Date.now();

        const response = await fetch(url, {
          method,
          headers: fetchHeaders,
          body: body || undefined,
          redirect: followRedirects ? "follow" : "manual",
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

        const responseTimeMs = Date.now() - startTime;

        return {
          success: true,
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
          body:
            responseBody.length > 5000
              ? `${responseBody.substring(0, 5000)}...\n\n(truncated) use execute_command with grep / tail to paginate the response`
              : responseBody,
          url: response.url,
          redirected: response.redirected,
          responseTimeMs,
        };
      } catch (error: unknown) {
        if (timeoutId) clearTimeout(timeoutId);

        const isAbort = error instanceof Error && error.name === "AbortError";
        const errorMsg = isAbort
          ? ctx.abortSignal?.aborted
            ? "Request aborted by user"
            : `Request timeout after ${timeout}ms`
          : error instanceof Error
            ? error.message
            : String(error);

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
          responseTimeMs: 0,
        };
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
    rawHeaders?: [string, string][];
    body?: string;
    followRedirects: boolean;
    timeout: number;
  },
): Promise<HttpRequestResult> {
  const { url, method, headers, rawHeaders, body, followRedirects, timeout } =
    opts;

  try {
    let curlCommand = `curl -i -X ${method}`;

    // rawHeaders takes precedence — each tuple becomes a separate -H flag (supports duplicates)
    if (rawHeaders) {
      for (const [key, value] of rawHeaders) {
        curlCommand += ` -H "${key}: ${value}"`;
      }
    } else if (headers) {
      for (const [key, value] of Object.entries(headers)) {
        curlCommand += ` -H "${key}: ${value}"`;
      }
    }

    if (body && ["POST", "PUT", "PATCH"].includes(method)) {
      const escapedBody = body.replace(/"/g, '\\"').replace(/\$/g, "\\$");
      curlCommand += ` -d "${escapedBody}"`;
    }

    if (followRedirects) {
      curlCommand += " -L";
    }

    const timeoutSeconds = Math.ceil(timeout / 1000);
    curlCommand += ` --max-time ${timeoutSeconds}`;
    curlCommand += ` --write-out "\\n__APEX_TIMING__:%{time_total}"`;
    curlCommand += ` "${url}" 2>&1`;

    const ssmTimeout = Math.max(timeoutSeconds, 30);
    const result = await ctx.sandbox!.execute(curlCommand, {
      timeout: ssmTimeout,
    });

    const rawOutput = result.stdout || "";

    // Extract timing from __APEX_TIMING__ marker appended by --write-out
    let responseTimeMs = 0;
    const timingMatch = rawOutput.match(/__APEX_TIMING__:([\d.]+)/);
    if (timingMatch) {
      responseTimeMs = Math.round(parseFloat(timingMatch[1]) * 1000);
    }

    // Strip the timing marker from output before parsing headers/body
    const output = rawOutput.replace(/\n?__APEX_TIMING__:[\d.]+/, "");
    const lines = output.split("\n");
    let statusLine = "";
    const responseHeaders: Record<string, string> = {};
    let bodyStartIndex = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.startsWith("HTTP/")) {
        statusLine = line;
        for (let j = i + 1; j < lines.length; j++) {
          if (lines[j].trim() === "") {
            bodyStartIndex = j + 1;
            break;
          }
          const headerMatch = lines[j].match(/^([^:]+):\s*(.+)$/);
          if (headerMatch) {
            responseHeaders[headerMatch[1].toLowerCase()] = headerMatch[2];
          }
        }
        break;
      }
    }

    const statusMatch = statusLine.match(/HTTP\/[\d.]+\s+(\d+)\s+(.+)/);
    const status = statusMatch ? parseInt(statusMatch[1]) : 0;
    const statusText = statusMatch ? statusMatch[2] : "Unknown";
    const responseBody = lines.slice(bodyStartIndex).join("\n");

    return {
      success: status >= 200 && status < 400,
      status,
      statusText,
      headers: responseHeaders,
      body:
        responseBody.length > 5000
          ? `${responseBody.substring(0, 5000)}...\n\n(truncated) use execute_command with grep / tail to paginate the response`
          : responseBody,
      url,
      redirected: false,
      responseTimeMs,
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
      responseTimeMs: 0,
    };
  }
}
