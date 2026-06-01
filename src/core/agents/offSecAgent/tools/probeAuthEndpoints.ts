import { tool } from "ai";
import { z } from "zod";
import { targetFetch } from "../../../http/targetHeaders";
import {
  assertUrlInScope,
  resolverSessionFromCtx,
  ScopeViolationError,
} from "./scopeGuard";
import type { ToolContext } from "./types";

const AUTH_ENDPOINT_PATTERNS = {
  login: [
    "/api/login",
    "/api/auth/login",
    "/api/v1/login",
    "/api/v1/auth/login",
    "/api/signin",
    "/api/auth/signin",
    "/api/authenticate",
    "/auth/login",
    "/auth/signin",
    "/login",
    "/signin",
  ],
  token: [
    "/api/token",
    "/api/auth/token",
    "/api/oauth/token",
    "/oauth/token",
    "/token",
    "/api/session",
  ],
  user: [
    "/api/me",
    "/api/user",
    "/api/profile",
    "/api/users/me",
    "/me",
    "/user",
    "/api/account",
    "/account",
  ],
  refresh: [
    "/api/refresh",
    "/api/auth/refresh",
    "/api/token/refresh",
    "/refresh",
  ],
  protected: [
    "/api/data",
    "/api/protected",
    "/api/private",
    "/api/secure",
    "/data",
    "/protected",
    "/private",
    "/secure",
    "/api/v1/data",
    "/api/v1/protected",
    "/admin",
    "/api/admin",
    "/dashboard",
    "/api/dashboard",
  ],
};

/**
 * Factory for the `probe_auth_endpoints` tool.
 *
 * Probes ~40 common auth endpoint paths with GET and POST to discover
 * login, token, user, refresh, and protected resource endpoints.
 */
export function probeAuthEndpoints(ctx: ToolContext) {
  return tool({
    description: `Probe common authentication endpoint patterns to discover where to authenticate.

Use this when:
- Target endpoint returns 404 or no clear auth scheme detected
- Need to find login/token endpoints for JSON APIs
- detect_auth_scheme didn't find form or auth headers

Probes ~40 common paths with both GET and POST methods:
- Login endpoints: /api/login, /api/auth/login, /login, etc.
- Token endpoints: /api/token, /oauth/token, etc.
- User endpoints: /api/me, /api/user, etc.
- Protected resources: /api/data, /api/protected, /admin, etc.

Returns discovered endpoints and recommended login approach.`,
    inputSchema: z.object({
      baseUrl: z
        .string()
        .describe("Base URL to probe (e.g., https://example.com)"),
      toolCallDescription: z
        .string()
        .describe("A concise description of what this tool call is doing"),
    }),
    execute: async ({ baseUrl }) => {
      try {
        assertUrlInScope(baseUrl, ctx);
      } catch (e) {
        if (e instanceof ScopeViolationError) {
          return {
            success: false,
            endpoints: [],
            message: e.message,
          };
        }
        throw e;
      }

      const discoveredEndpoints: Array<{
        path: string;
        methods: string[];
        authIndicators: string[];
        likelyPurpose: string;
      }> = [];

      const allPatterns = [
        ...AUTH_ENDPOINT_PATTERNS.login.map((p) => ({
          path: p,
          purpose: "login",
        })),
        ...AUTH_ENDPOINT_PATTERNS.token.map((p) => ({
          path: p,
          purpose: "token",
        })),
        ...AUTH_ENDPOINT_PATTERNS.user.map((p) => ({
          path: p,
          purpose: "user",
        })),
        ...AUTH_ENDPOINT_PATTERNS.refresh.map((p) => ({
          path: p,
          purpose: "refresh",
        })),
        ...AUTH_ENDPOINT_PATTERNS.protected.map((p) => ({
          path: p,
          purpose: "protected",
        })),
      ];

      for (const { path, purpose } of allPatterns) {
        if (ctx.abortSignal?.aborted) break;

        const url = baseUrl.replace(/\/$/, "") + path;
        const methods: string[] = [];
        const authIndicators: string[] = [];

        // Try GET
        try {
          const getResult = await targetFetch(
            resolverSessionFromCtx(ctx),
            url,
            {
              method: "GET",
              signal: ctx.abortSignal,
            },
          );
          if (getResult.status !== 404 && getResult.status !== 0) {
            methods.push("GET");
            if (getResult.status === 401)
              authIndicators.push("requires auth (401)");
            if (getResult.status === 200)
              authIndicators.push("accessible (200)");
            if (getResult.status === 403)
              authIndicators.push("forbidden (403)");

            const wwwAuth = getResult.headers.get("www-authenticate");
            if (wwwAuth) {
              if (wwwAuth.toLowerCase().includes("basic"))
                authIndicators.push("HTTP Basic Auth");
              if (wwwAuth.toLowerCase().includes("bearer"))
                authIndicators.push("Bearer token required");
            }
          }
        } catch {
          // Ignore individual errors
        }

        // Try POST with empty JSON
        try {
          const postResult = await targetFetch(
            resolverSessionFromCtx(ctx),
            url,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: "{}",
              signal: ctx.abortSignal,
            },
          );
          if (postResult.status !== 404 && postResult.status !== 0) {
            methods.push("POST");
            const body = await postResult.text();
            if (postResult.status === 400)
              authIndicators.push("expects body (400)");
            if (postResult.status === 401)
              authIndicators.push("invalid credentials (401)");
            if (postResult.status === 200)
              authIndicators.push("POST accessible (200)");
            if (body.includes("username") || body.includes("password"))
              authIndicators.push("expects credentials");
            if (body.includes("token") || body.includes("jwt"))
              authIndicators.push("returns tokens");
          }
        } catch {
          // Ignore individual errors
        }

        if (methods.length > 0) {
          discoveredEndpoints.push({
            path,
            methods,
            authIndicators,
            likelyPurpose: purpose,
          });
        }
      }

      const basicAuthEndpoint = discoveredEndpoints.find((e) =>
        e.authIndicators.includes("HTTP Basic Auth"),
      );

      const loginEndpoint =
        discoveredEndpoints.find(
          (e) =>
            e.likelyPurpose === "login" &&
            e.methods.includes("POST") &&
            (e.authIndicators.includes("expects body (400)") ||
              e.authIndicators.includes("invalid credentials (401)") ||
              e.authIndicators.includes("expects credentials")),
        ) ||
        discoveredEndpoints.find(
          (e) => e.likelyPurpose === "login" && e.methods.includes("POST"),
        );

      let message = "";
      if (discoveredEndpoints.length === 0) {
        message = "No auth endpoints found at common paths";
      } else if (basicAuthEndpoint) {
        message = `Found HTTP Basic Auth at ${basicAuthEndpoint.path}. Use Authorization: Basic base64(user:pass).`;
      } else if (loginEndpoint) {
        message = `Found ${discoveredEndpoints.length} auth endpoints. Recommended: POST ${loginEndpoint.path}`;
      } else {
        message = `Found ${discoveredEndpoints.length} potential auth endpoints`;
      }

      return {
        success: true,
        endpoints: discoveredEndpoints,
        recommendedLoginEndpoint:
          basicAuthEndpoint?.path || loginEndpoint?.path,
        recommendedMethod: basicAuthEndpoint
          ? "GET (with Basic Auth header)"
          : loginEndpoint
            ? "POST"
            : undefined,
        message,
      };
    },
  });
}
