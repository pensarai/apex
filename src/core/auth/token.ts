import { config } from "../config";
// Importing through the api barrel would cycle. Use the leaf constants
// module directly.
import { getPensarApiUrl } from "../api/constants";
import type { ValidToken } from "./types";

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

/**
 * Refresh a WorkOS access token using the refresh token.
 * Updates the stored config with new tokens on success.
 *
 * @returns The new access token, or null if refresh fails
 */
export async function refreshAccessToken(
  clientId: string,
  refreshToken: string,
): Promise<string | null> {
  try {
    const response = await fetch(
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

    if (!response.ok) {
      console.error(
        `[pensar] Token refresh failed: ${response.status} ${response.statusText}`,
      );
      return null;
    }

    const data = (await response.json()) as {
      access_token: string;
      refresh_token: string;
    };

    await config.update({
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
    });

    return data.access_token;
  } catch (err) {
    console.error("[pensar] Token refresh error:", err);
    return null;
  }
}

/**
 * Ensure a valid access token is available.
 * If the current token is expired, attempts to refresh it.
 *
 * @returns A valid access token, or null if no valid token is available
 */
export async function ensureValidToken(cfg: {
  accessToken?: string | null;
  refreshToken?: string | null;
  pensarAPIKey?: string | null;
}): Promise<ValidToken | null> {
  if (cfg.accessToken) {
    if (!isTokenExpired(cfg.accessToken)) {
      return { token: cfg.accessToken, type: "workos" };
    }

    if (cfg.refreshToken) {
      const clientId = await fetchWorkOSClientId();
      if (clientId) {
        const newToken = await refreshAccessToken(clientId, cfg.refreshToken);
        if (newToken) {
          return { token: newToken, type: "workos" };
        }
      }
    }
  }

  if (cfg.pensarAPIKey) {
    return { token: cfg.pensarAPIKey, type: "legacy" };
  }

  return null;
}
