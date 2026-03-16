import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync } from "fs";
import type { ToolContext } from "./types";

/**
 * Factory for the `authenticate_session` tool.
 *
 * Performs simple credential-based authentication (form POST, JSON POST,
 * or HTTP Basic) and persists the resulting session cookie for reuse
 * by other tools.
 *
 * Supports two modes:
 * 1. **Credential ID** — pass a `credentialId` obtained from the
 *    credential manager. The tool resolves the full secret internally.
 * 2. **Direct credentials** — pass `username` / `password` directly
 *    (legacy behaviour, still supported for backward compatibility).
 */
export function authenticateSession(ctx: ToolContext) {
  return tool({
    description: `Authenticate with credentials and obtain a session cookie for subsequent authenticated requests.

Use this to:
- Test discovered credentials
- Obtain session cookies for authenticated exploration
- Access protected areas of the application

You can either pass a credentialId (preferred when credentials are managed)
or provide username/password directly.`,
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
      additionalFields: z.preprocess(
        (val) => (typeof val === "string" ? JSON.parse(val) : val),
        z
          .record(z.string(), z.string())
          .optional()
          .describe("Additional form fields (e.g., csrf tokens)"),
      ),
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

        const setCookieHeader = result.headers?.getSetCookie() || [];
        const sessionCookies = Array.isArray(setCookieHeader)
          ? setCookieHeader
          : [setCookieHeader];
        const cookieString = sessionCookies.join("; ");

        const authenticated =
          result.status >= 200 &&
          result.status < 400 &&
          cookieString.length > 0;

        // Save session info for reuse
        const sessionInfoPath = join(ctx.session.rootPath, "session-info.json");
        const sessionInfo = {
          authenticated,
          username,
          sessionCookie: cookieString,
          loginUrl,
          timestamp: new Date().toISOString(),
        };
        writeFileSync(sessionInfoPath, JSON.stringify(sessionInfo, null, 2));

        return {
          success: authenticated,
          authenticated,
          sessionCookie: cookieString,
          statusCode: result.status,
          message: authenticated
            ? `Successfully authenticated as ${username}. Session cookie saved for use with other tools.`
            : `Authentication failed. Status: ${result.status}.`,
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
