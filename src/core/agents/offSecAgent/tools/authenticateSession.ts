import { tool } from "ai";
import { writeFileSync } from "fs";
import { join } from "path";
import { z } from "zod";
import type { ToolContext } from "./types";

/**
 * Factory for the `authenticate_session` tool.
 *
 * Performs simple credential-based authentication (form POST, JSON POST,
 * or HTTP Basic) and persists the resulting session credentials for reuse
 * by other tools. Supports both cookie-based sessions and JWT/Bearer
 * token responses (e.g. `{ access_token, refresh_token }` JSON bodies).
 *
 * Supports two modes:
 * 1. **Credential ID** — pass a `credentialId` obtained from the
 *    credential manager. The tool resolves the full secret internally.
 * 2. **Direct credentials** — pass `username` / `password` directly
 *    (legacy behaviour, still supported for backward compatibility).
 */
export function authenticateSession(ctx: ToolContext) {
  return tool({
    description: `Authenticate with credentials and obtain a session for subsequent authenticated requests.

Use this to:
- Test discovered credentials
- Obtain session cookies OR bearer/JWT tokens for authenticated exploration
- Access protected areas of the application

You can either pass a credentialId (preferred when credentials are managed)
or provide username/password directly.

On success, the tool persists session credentials to <session>/session-info.json
and returns:
- sessionCookie: a "name=value; name=value" string when the server sets cookies
- bearerToken + authorizationHeader: when the server returns a JWT/access token in a JSON body
  (looks for access_token, accessToken, token, jwt, id_token, idToken, authToken, auth_token)
- refreshToken: when the JSON body includes one

On failure (non-2xx, or 2xx without a recognizable session artifact), the tool
returns the status code AND a truncated responseBody so you can diagnose:
- 405 → loginUrl is a page route, not the API endpoint; re-read credential context
- 422/400 → wrong body shape; check Content-Type and field names in credential context
- 401 → credentials are wrong; do NOT probe further, report failure`,
    inputSchema: z.object({
      loginUrl: z
        .string()
        .optional()
        .describe(
          "Login endpoint URL. Can be omitted when using a credentialId that includes a loginUrl.",
        ),
      credentialId: z
        .string()
        .optional()
        .describe(
          "ID of a stored credential to use. When provided, username/password are resolved automatically.",
        ),
      username: z
        .string()
        .optional()
        .describe(
          "Username to authenticate with (ignored if credentialId is set)",
        ),
      password: z
        .string()
        .optional()
        .describe(
          "Password to authenticate with (ignored if credentialId is set)",
        ),
      method: z
        .enum(["form_post", "json_post", "basic_auth"])
        .default("form_post")
        .describe("Authentication method"),
      usernameField: z
        .string()
        .default("username")
        .describe("Name of username field"),
      passwordField: z
        .string()
        .default("password")
        .describe("Name of password field"),
      additionalFields: z
        .record(z.string(), z.string())
        .optional()
        .describe("Additional form fields (e.g., csrf tokens)"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async (params) => {
      try {
        let { loginUrl, username, password } = params;
        const {
          credentialId,
          method,
          usernameField,
          passwordField,
          additionalFields,
        } = params;

        // Resolve credential from manager when an ID is provided
        if (credentialId && ctx.credentialManager) {
          const stored = ctx.credentialManager.resolve(credentialId);
          if (!stored) {
            return {
              success: false,
              authenticated: false,
              message: `Unknown credential ID: ${credentialId}`,
            };
          }
          username = stored.username ?? username;
          password = stored.password ?? password;
          if (stored.loginUrl && !loginUrl) loginUrl = stored.loginUrl;
        }

        if (!username || !password) {
          return {
            success: false,
            authenticated: false,
            message:
              "Username and password are required. Provide them directly or via a credentialId.",
          };
        }

        if (!loginUrl) {
          return {
            success: false,
            authenticated: false,
            message:
              "loginUrl is required. Provide it directly or via a credentialId that includes one.",
          };
        }

        const authRequest: RequestInit = { method: "POST" };

        if (method === "form_post") {
          const formData = {
            [usernameField]: username,
            [passwordField]: password,
            ...additionalFields,
          };
          authRequest.body = new URLSearchParams(formData).toString();
          authRequest.headers = {
            "Content-Type": "application/x-www-form-urlencoded",
          };
        } else if (method === "json_post") {
          authRequest.body = JSON.stringify({
            [usernameField]: username,
            [passwordField]: password,
            ...additionalFields,
          });
          authRequest.headers = { "Content-Type": "application/json" };
        } else if (method === "basic_auth") {
          const authHeader = Buffer.from(`${username}:${password}`).toString(
            "base64",
          );
          authRequest.headers = { Authorization: `Basic ${authHeader}` };
        }

        const result = await fetch(loginUrl, authRequest);

        const { sessionCookie, bearerToken, refreshToken, bodyPreview } =
          await extractAuthArtifacts(result);

        const statusOk = result.status >= 200 && result.status < 400;
        const authenticated =
          statusOk && (sessionCookie.length > 0 || bearerToken.length > 0);

        const authorizationHeader = bearerToken ? `Bearer ${bearerToken}` : "";

        // Save session info for reuse. Body preview is intentionally NOT
        // persisted on success (it would leak the token to anything that
        // tails the file); persist only the structured artifacts.
        const sessionInfoPath = join(ctx.session.rootPath, "session-info.json");
        const sessionInfo = {
          authenticated,
          username,
          loginUrl,
          strategy: method,
          sessionCookie,
          bearerToken,
          refreshToken,
          authorizationHeader,
          timestamp: new Date().toISOString(),
        };
        writeFileSync(sessionInfoPath, JSON.stringify(sessionInfo, null, 2));

        return {
          success: authenticated,
          authenticated,
          statusCode: result.status,
          sessionCookie,
          bearerToken,
          refreshToken,
          authorizationHeader,
          // Expose body preview to the agent so it can diagnose failures
          // (e.g. 422 "field required" hints, 405 HTML error pages).
          // On success we still include a short preview unless it embeds
          // the bearer token (in which case it's scrubbed below).
          responseBody: authenticated
            ? scrubTokens(bodyPreview, [bearerToken, refreshToken])
            : bodyPreview,
          message: buildMessage({
            authenticated,
            statusCode: result.status,
            username,
            sessionCookie,
            bearerToken,
            bodyPreview,
          }),
        };
      } catch (error: unknown) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          authenticated: false,
          message: `Authentication error: ${errorMsg}`,
        };
      }
    },
  });
}

// ---------------------------------------------------------------------------
// Helpers (exported for unit tests)
// ---------------------------------------------------------------------------

/**
 * Keys commonly used by token-returning auth endpoints. Order matters —
 * we prefer access_token / accessToken over generic `token` to avoid
 * picking up CSRF tokens or other unrelated fields.
 */
const BEARER_TOKEN_KEYS = [
  "access_token",
  "accessToken",
  "id_token",
  "idToken",
  "auth_token",
  "authToken",
  "jwt",
  "token",
] as const;

const REFRESH_TOKEN_KEYS = ["refresh_token", "refreshToken"] as const;

const BODY_PREVIEW_LIMIT = 800;

/**
 * Inspect a JSON-shaped value for a likely bearer token. Returns "" if none.
 * Exported for testing.
 */
export function extractBearerToken(parsed: unknown): string {
  if (!parsed || typeof parsed !== "object") return "";
  const obj = parsed as Record<string, unknown>;
  for (const key of BEARER_TOKEN_KEYS) {
    const v = obj[key];
    if (typeof v === "string" && v.length > 0) return v;
  }
  // Some APIs nest tokens under `data` / `result` / `auth`. Check one level deep.
  for (const wrapper of ["data", "result", "auth", "session"]) {
    const inner = obj[wrapper];
    if (inner && typeof inner === "object") {
      const nested = extractBearerToken(inner);
      if (nested) return nested;
    }
  }
  return "";
}

export function extractRefreshToken(parsed: unknown): string {
  if (!parsed || typeof parsed !== "object") return "";
  const obj = parsed as Record<string, unknown>;
  for (const key of REFRESH_TOKEN_KEYS) {
    const v = obj[key];
    if (typeof v === "string" && v.length > 0) return v;
  }
  for (const wrapper of ["data", "result", "auth", "session"]) {
    const inner = obj[wrapper];
    if (inner && typeof inner === "object") {
      const nested = extractRefreshToken(inner);
      if (nested) return nested;
    }
  }
  return "";
}

interface AuthArtifacts {
  sessionCookie: string;
  bearerToken: string;
  refreshToken: string;
  bodyPreview: string;
}

/**
 * Pull session credentials out of a Response: cookies via Set-Cookie,
 * bearer/refresh tokens via JSON body. Body is consumed via clone() so the
 * caller can still read it elsewhere if needed.
 *
 * Exported for testing.
 */
export async function extractAuthArtifacts(
  response: Response,
): Promise<AuthArtifacts> {
  const setCookie = response.headers?.getSetCookie?.() ?? [];
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  const sessionCookie = cookies.filter(Boolean).join("; ");

  let bearerToken = "";
  let refreshToken = "";
  let bodyPreview = "";

  try {
    const raw = await response.clone().text();
    bodyPreview =
      raw.length > BODY_PREVIEW_LIMIT
        ? `${raw.slice(0, BODY_PREVIEW_LIMIT)}…`
        : raw;

    const contentType = response.headers.get("content-type") ?? "";
    if (contentType.includes("application/json") && raw) {
      try {
        const parsed = JSON.parse(raw);
        bearerToken = extractBearerToken(parsed);
        refreshToken = extractRefreshToken(parsed);
      } catch {
        // Server lied about Content-Type; nothing actionable here.
      }
    }
  } catch {
    // Body unreadable (already consumed, network error after headers, etc.)
  }

  return { sessionCookie, bearerToken, refreshToken, bodyPreview };
}

function scrubTokens(text: string, tokens: string[]): string {
  let out = text;
  for (const t of tokens) {
    if (t && t.length > 6) {
      out = out.split(t).join("<redacted>");
    }
  }
  return out;
}

function buildMessage(opts: {
  authenticated: boolean;
  statusCode: number;
  username: string;
  sessionCookie: string;
  bearerToken: string;
  bodyPreview: string;
}): string {
  const { authenticated, statusCode, username, sessionCookie, bearerToken } =
    opts;

  if (authenticated) {
    if (bearerToken && sessionCookie) {
      return `Successfully authenticated as ${username}. Both bearer token and session cookie obtained. Use the Authorization header on subsequent requests.`;
    }
    if (bearerToken) {
      return `Successfully authenticated as ${username}. Bearer token obtained — use Authorization: Bearer <token> on subsequent requests.`;
    }
    return `Successfully authenticated as ${username}. Session cookie saved for use with other tools.`;
  }

  // Failure messaging — give the agent enough to choose the next step.
  const hint =
    statusCode === 405
      ? " Status 405 means this URL is not an API endpoint (likely a page route). Re-read the credential Context for the real auth endpoint."
      : statusCode === 422 || statusCode === 400
        ? " Status indicates a malformed body. Check the credential Context for required Content-Type and field names (e.g. form-encoded vs JSON, 'username' vs 'email')."
        : statusCode === 401
          ? " Status 401 means the credentials are wrong — do not retry with a different endpoint. Report failure via complete_authentication."
          : statusCode === 404
            ? " Status 404 means the endpoint path is wrong. Try probe_auth_endpoints against the base URL."
            : statusCode >= 200 && statusCode < 400
              ? " Status was 2xx but no Set-Cookie or recognizable bearer token (access_token, accessToken, token, jwt, id_token) was found. Inspect responseBody — the token may be under an unexpected field."
              : "";

  const body = opts.bodyPreview
    ? ` Body: ${opts.bodyPreview.slice(0, 200)}`
    : "";

  return `Authentication failed. Status: ${statusCode}.${hint}${body}`;
}
