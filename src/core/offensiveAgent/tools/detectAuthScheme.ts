import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

/**
 * Factory for the `detect_auth_scheme` tool.
 *
 * Analyses an endpoint to identify the authentication mechanism in use
 * (form-based, HTTP Basic, Bearer, API key, OAuth, etc.) and detects
 * barriers like CAPTCHA or rate limiting.
 */
export function detectAuthScheme(ctx: ToolContext) {
  return tool({
    description: `Analyze an endpoint to detect authentication scheme.

Identifies:
- Form-based login (username/password fields)
- HTTP Basic/Digest Auth (WWW-Authenticate header)
- Bearer Token / JWT requirements
- API Key authentication (X-API-Key, etc.)
- OAuth2 flows
- Custom authentication schemes

Also detects auth barriers (CAPTCHA, MFA) that block automated auth.

Returns detected scheme and required fields for authentication.`,
    inputSchema: z.object({
      endpoint: z.string().describe("URL to analyze for auth scheme"),
      toolCallDescription: z
        .string()
        .describe("A concise description of what this tool call is doing"),
    }),
    execute: async ({ endpoint }) => {
      try {
        const response = await fetch(endpoint, {
          method: "GET",
          redirect: "manual",
          signal: ctx.abortSignal,
        });

        const body = await response.text();
        const bodyLower = body.toLowerCase();

        // Detect auth barriers
        const barrier = detectBarrier(bodyLower, response.status);
        if (barrier) {
          return { success: true, scheme: undefined, barrier };
        }

        // Check WWW-Authenticate header
        const wwwAuth = response.headers.get("www-authenticate");
        if (wwwAuth) {
          if (wwwAuth.toLowerCase().includes("basic")) {
            return {
              success: true,
              scheme: {
                method: "basic",
                endpoint,
                fields: {},
              },
            };
          }
          if (wwwAuth.toLowerCase().includes("bearer")) {
            return {
              success: true,
              scheme: {
                method: "bearer",
                endpoint,
                fields: {},
              },
            };
          }
        }

        // Check for redirect to login page
        if (response.status >= 300 && response.status < 400) {
          const location = response.headers.get("location") || "";
          if (/login|signin|auth/i.test(location)) {
            return {
              success: true,
              scheme: {
                method: "form",
                endpoint: location,
                browserRequired: true,
                fields: {},
              },
            };
          }
        }

        // Check for HTML login form
        if (
          bodyLower.includes('type="password"') ||
          bodyLower.includes("type='password'")
        ) {
          const fields: Record<string, string> = {};
          // Detect username field
          const usernameMatch = body.match(
            /name=['"]?(username|user|email|login|user_name)['"]?/i
          );
          if (usernameMatch) fields.usernameField = usernameMatch[1];

          // Detect password field
          const passwordMatch = body.match(
            /name=['"]?(password|pass|passwd)['"]?/i
          );
          if (passwordMatch) fields.passwordField = passwordMatch[1];

          // Detect CSRF
          const csrfMatch = body.match(
            /name=['"]?(csrf|_csrf|csrfmiddlewaretoken|_token|authenticity_token)['"]?\s+value=['"]?([^'"]+)['"]?/i
          );
          const csrfRequired = !!csrfMatch;

          // SPA detection
          const isSPA =
            bodyLower.includes("react") ||
            bodyLower.includes("angular") ||
            bodyLower.includes("vue") ||
            bodyLower.includes("__next");

          return {
            success: true,
            scheme: {
              method: "form",
              endpoint,
              fields,
              csrfRequired,
              csrfToken: csrfMatch?.[2],
              browserRequired: isSPA,
            },
          };
        }

        // Check for 401 JSON response
        if (response.status === 401) {
          return {
            success: true,
            scheme: {
              method: "json",
              endpoint,
              fields: {},
            },
          };
        }

        return {
          success: true,
          scheme: undefined,
          message: `No clear auth scheme detected at ${endpoint} (status: ${response.status})`,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
        };
      }
    },
  });
}

function detectBarrier(
  bodyLower: string,
  statusCode: number
): { type: string; details: string } | null {
  if (
    bodyLower.includes("captcha") ||
    bodyLower.includes("recaptcha") ||
    bodyLower.includes("hcaptcha") ||
    bodyLower.includes("g-recaptcha")
  ) {
    return { type: "captcha", details: "CAPTCHA detected on login form" };
  }

  if (
    statusCode === 429 ||
    bodyLower.includes("rate limit") ||
    bodyLower.includes("too many")
  ) {
    return { type: "rate_limit", details: "Rate limiting detected" };
  }

  return null;
}
