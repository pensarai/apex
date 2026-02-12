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
  followRedirects: z
    .boolean()
    .default(false)
    .describe(
      "Whether to follow HTTP redirects (3xx). Defaults to false so you can see redirect responses with Location and Set-Cookie headers."
    ),
  timeout: z.number().default(10000),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Testing SQL injection on login endpoint')"
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
- Monitor response times for blind injection attacks
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
      body,
      followRedirects,
      timeout,
    }): Promise<HttpRequestResult> => {
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
          };
        }

        const timeoutController = new AbortController();
        timeoutId = setTimeout(() => timeoutController.abort(), timeout);

        const combinedSignal = ctx.abortSignal
          ? AbortSignal.any([ctx.abortSignal, timeoutController.signal])
          : timeoutController.signal;

        const response = await fetch(url, {
          method,
          headers: headers || {},
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
        };
      } catch (error: any) {
        if (timeoutId) clearTimeout(timeoutId);

        const errorMsg =
          error.name === "AbortError"
            ? ctx.abortSignal?.aborted
              ? "Request aborted by user"
              : `Request timeout after ${timeout}ms`
            : error.message;

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
        };
      }
    },
  });
}
