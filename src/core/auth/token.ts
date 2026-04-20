import { config } from "../config";
import { getPensarApiUrl } from "../api/constants";
import type { ValidToken } from "./types";

export type ApexAuthReason =
  | "refresh_http_error"
  | "refresh_exception"
  | "workos_config_unavailable"
  | "session_dead"
  | "no_credentials";

export class ApexAuthError extends Error {
  readonly reason: ApexAuthReason;
  readonly status?: number;
  readonly body?: string;

  constructor(opts: {
    reason: ApexAuthReason;
    message?: string;
    status?: number;
    body?: string;
  }) {
    super(opts.message ?? `Apex auth error: ${opts.reason}`);
    this.name = "ApexAuthError";
    this.reason = opts.reason;
    this.status = opts.status;
    this.body = opts.body;
  }
}

export function isApexAuthError(err: unknown): err is ApexAuthError {
  return err instanceof ApexAuthError;
}

/**
 * Decode a JWT payload without verifying the signature.
 * Used client-side to check token expiry before making API calls.
 */
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1], "base64url").toString("utf-8");
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

/**
 * Check if a JWT access token is expired or about to expire.
 * Returns true if the token should be refreshed (expires within bufferSeconds).
 */
export function isTokenExpired(
  token: string,
  bufferSeconds: number = 60,
): boolean {
  const payload = decodeJwtPayload(token);
  if (!payload || typeof payload.exp !== "number") return true;

  const nowSeconds = Math.floor(Date.now() / 1000);
  return payload.exp - nowSeconds < bufferSeconds;
}

/**
 * Fetch the WorkOS client ID from the CLI config endpoint.
 * Caches the result for the lifetime of the process.
 */
let cachedClientId: string | null = null;

export async function fetchWorkOSClientId(): Promise<string | null> {
  if (cachedClientId) return cachedClientId;

  try {
    const apiUrl = getPensarApiUrl();
    const response = await fetch(`${apiUrl}/api/cli/config`);

    if (!response.ok) return null;

    const data = (await response.json()) as { workosClientId: string };
    cachedClientId = data.workosClientId;
    return cachedClientId;
  } catch {
    return null;
  }
}

// Serializes concurrent refresh attempts. WorkOS refresh tokens rotate on
// every use, so two parallel callers using the same refresh_token would cause
// the second to fail with an already-rotated token.
let inFlightRefresh: Promise<string> | null = null;

async function doRefresh(
  clientId: string,
  refreshToken: string,
): Promise<string> {
  let response: Response;
  try {
    response = await fetch(
      "https://api.workos.com/user_management/authenticate",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: clientId,
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }),
      },
    );
  } catch (err) {
    throw new ApexAuthError({
      reason: "refresh_exception",
      message: `Token refresh network error: ${err instanceof Error ? err.message : String(err)}`,
    });
  }

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new ApexAuthError({
      reason: "refresh_http_error",
      message: `Token refresh failed: ${response.status} ${response.statusText}`,
      status: response.status,
      body,
    });
  }

  const data = (await response.json()) as {
    access_token: string;
    refresh_token: string;
  };

  const now = new Date().toISOString();
  await config.update({
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    accessTokenIssuedAt: now,
    refreshTokenIssuedAt: now,
  });

  return data.access_token;
}

/**
 * Refresh a WorkOS access token using the refresh token.
 * Updates the stored config with new tokens on success.
 *
 * @returns The new access token.
 * @throws  ApexAuthError on any refresh failure.
 */
export async function refreshAccessToken(
  clientId: string,
  refreshToken: string,
): Promise<string> {
  if (inFlightRefresh) return inFlightRefresh;
  inFlightRefresh = doRefresh(clientId, refreshToken).finally(() => {
    inFlightRefresh = null;
  });
  return inFlightRefresh;
}

export interface EnsureValidTokenOptions {
  /** Skip the access-token `exp` check and always attempt a refresh. */
  forceRefresh?: boolean;
}

/**
 * Ensure a valid access token is available.
 * If the current token is expired, attempts to refresh it.
 *
 * @returns A valid access token, or null if no valid token is available.
 *          Returns null for both "not logged in" and "refresh failed"; use
 *          ensureValidTokenOrThrow to distinguish.
 */
export async function ensureValidToken(
  cfg: {
    accessToken?: string | null;
    refreshToken?: string | null;
    pensarAPIKey?: string | null;
  },
  options: EnsureValidTokenOptions = {},
): Promise<ValidToken | null> {
  if (cfg.accessToken) {
    if (!options.forceRefresh && !isTokenExpired(cfg.accessToken)) {
      return { token: cfg.accessToken, type: "workos" };
    }

    if (cfg.refreshToken) {
      const clientId = await fetchWorkOSClientId();
      if (clientId) {
        try {
          const newToken = await refreshAccessToken(
            clientId,
            cfg.refreshToken,
          );
          return { token: newToken, type: "workos" };
        } catch (err) {
          if (isApexAuthError(err)) {
            // swallow here to preserve the existing null-on-failure contract;
            // ensureValidTokenOrThrow surfaces the typed error for callers
            // that need it (TUI preflight, 401 retry path).
            console.error(`[pensar] Token refresh failed: ${err.message}`);
          } else {
            console.error("[pensar] Token refresh error:", err);
          }
        }
      }
    }
  }

  if (cfg.pensarAPIKey) {
    return { token: cfg.pensarAPIKey, type: "legacy" };
  }

  return null;
}

/**
 * Like ensureValidToken, but throws ApexAuthError when the user is configured
 * but cannot produce a valid token (dead refresh, WorkOS unreachable, etc).
 * Used by the TUI startup preflight and the 401 retry path in pensar.ts.
 *
 * @throws ApexAuthError({ reason: 'no_credentials' }) when neither WorkOS
 *         tokens nor a legacy API key are configured.
 * @throws ApexAuthError({ reason: 'session_dead' }) when an access/refresh
 *         token exists but refresh fails.
 */
export async function ensureValidTokenOrThrow(
  cfg: {
    accessToken?: string | null;
    refreshToken?: string | null;
    pensarAPIKey?: string | null;
  },
  options: EnsureValidTokenOptions = {},
): Promise<ValidToken> {
  if (cfg.accessToken) {
    if (!options.forceRefresh && !isTokenExpired(cfg.accessToken)) {
      return { token: cfg.accessToken, type: "workos" };
    }

    if (!cfg.refreshToken) {
      if (cfg.pensarAPIKey) {
        return { token: cfg.pensarAPIKey, type: "legacy" };
      }
      throw new ApexAuthError({
        reason: "session_dead",
        message: "Access token expired and no refresh token available",
      });
    }

    const clientId = await fetchWorkOSClientId();
    if (!clientId) {
      throw new ApexAuthError({
        reason: "workos_config_unavailable",
        message: "Could not fetch WorkOS client config",
      });
    }

    const newToken = await refreshAccessToken(clientId, cfg.refreshToken);
    return { token: newToken, type: "workos" };
  }

  if (cfg.pensarAPIKey) {
    return { token: cfg.pensarAPIKey, type: "legacy" };
  }

  throw new ApexAuthError({ reason: "no_credentials" });
}
