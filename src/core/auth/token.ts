// Importing through the api barrel would cycle. Use the leaf constants
// module directly.
import { getPensarApiUrl } from "../api/constants";
import { config } from "../config";
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

async function fetchWorkOSClientId(): Promise<string | null> {
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

// WorkOS refresh tokens rotate on every use; serialize concurrent attempts.
let inFlightRefresh: Promise<string> | null = null;

async function doRefresh(
/**
 * Refresh a WorkOS access token using the refresh token.
 * Updates the stored config with new tokens on success.
 *
 * @returns The new access token, or null if refresh fails
 */
async function refreshAccessToken(
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

interface TokenCfg {
  accessToken?: string | null;
  refreshToken?: string | null;
  pensarAPIKey?: string | null;
}

/**
 * Throws ApexAuthError on any token failure (used by TUI preflight and 401 retry).
 *
 * @throws ApexAuthError with typed reason on any auth failure.
 */
export async function ensureValidTokenOrThrow(
  cfg: TokenCfg,
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

/**
 * Returns null on failure (for legacy callers). Use ensureValidTokenOrThrow for typed errors.
 */
export async function ensureValidToken(
  cfg: TokenCfg,
  options: EnsureValidTokenOptions = {},
): Promise<ValidToken | null> {
  try {
    return await ensureValidTokenOrThrow(cfg, options);
  } catch (err) {
    if (isApexAuthError(err)) {
      if (err.reason !== "no_credentials") {
        console.error(`[pensar] ${err.message}`);
      }
      return null;
    }
    throw err;
  }
}
