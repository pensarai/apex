// Importing through the api barrel would cycle. Use the leaf constants
// module directly.
import { getPensarApiUrl } from "../api/constants";
import type {
  DeviceFlowInfo,
  LegacyDeviceCodeResponse,
  LegacyTokenResponse,
  WorkOSDeviceResponse,
} from "./types";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Start a device-authorization flow.
 *
 * Tries the modern WorkOS flow first; if the backend does not support it
 * (older deployment), falls back to the legacy `/auth/device/code` endpoint.
 */
export async function startDeviceFlow(
  apiUrl?: string,
): Promise<DeviceFlowInfo> {
  const url = apiUrl ?? getPensarApiUrl();

  // Try WorkOS first
  try {
    const configResponse = await fetch(`${url}/api/cli/config`);
    if (configResponse.ok) {
      const cliConfig = (await configResponse.json()) as {
        workosClientId: string;
      };

      const response = await fetch(
        "https://api.workos.com/user_management/authorize/device",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ client_id: cliConfig.workosClientId }),
        },
      );

      if (response.ok) {
        const deviceInfo = (await response.json()) as WorkOSDeviceResponse;
        return {
          mode: "workos",
          clientId: cliConfig.workosClientId,
          deviceInfo,
        };
      }
    }
  } catch {
    // Fall through to legacy
  }

  // Legacy flow
  const response = await fetch(`${url}/auth/device/code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });

  if (!response.ok) {
    throw new Error("Failed to start device authorization");
  }

  const deviceInfo = (await response.json()) as LegacyDeviceCodeResponse;
  return { mode: "legacy", deviceInfo };
}

/**
 * Poll WorkOS for token completion after the user authorizes in-browser.
 *
 * Resolves with the token pair once the user completes authorization.
 * Rejects on timeout or fatal error. Pass an `AbortSignal` for cancellation.
 */
export async function pollWorkOSToken(params: {
  clientId: string;
  deviceCode: string;
  interval: number;
  expiresIn: number;
  signal?: AbortSignal;
}): Promise<{ accessToken: string; refreshToken: string }> {
  const { clientId, deviceCode, interval, expiresIn, signal } = params;
  const deadline = Date.now() + expiresIn * 1000;

  while (Date.now() < deadline) {
    if (signal?.aborted) throw new Error("Authorization cancelled");

    await sleep(interval * 1000);

    if (signal?.aborted) throw new Error("Authorization cancelled");

    try {
      const response = await fetch(
        "https://api.workos.com/user_management/authenticate",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client_id: clientId,
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            device_code: deviceCode,
          }),
        },
      );

      if (response.status === 400) {
        continue; // authorization_pending
      }

      if (!response.ok) {
        throw new Error("Authentication failed");
      }

      const data = (await response.json()) as {
        access_token: string;
        refresh_token: string;
      };

      return {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
      };
    } catch (err) {
      if (
        err instanceof Error &&
        (err.message === "Authentication failed" ||
          err.message === "Authorization cancelled")
      ) {
        throw err;
      }
      // Network glitch — retry
    }
  }

  throw new Error("Authorization timed out. Please try again.");
}

/**
 * Poll the legacy device-token endpoint for completion.
 *
 * Resolves with the full legacy token response (API key, workspace, etc.).
 * Rejects on timeout, expiry, or fatal error.
 */
export async function pollLegacyToken(params: {
  apiUrl: string;
  deviceCode: string;
  interval: number;
  expiresIn: number;
  signal?: AbortSignal;
}): Promise<LegacyTokenResponse> {
  const { apiUrl, deviceCode, interval, expiresIn, signal } = params;
  const deadline = Date.now() + expiresIn * 1000;

  while (Date.now() < deadline) {
    if (signal?.aborted) throw new Error("Authorization cancelled");

    await sleep(interval * 1000);

    if (signal?.aborted) throw new Error("Authorization cancelled");

    try {
      const response = await fetch(`${apiUrl}/auth/device/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ deviceCode }),
      });

      if (!response.ok) continue;

      const data = (await response.json()) as LegacyTokenResponse;

      if (data.status === "complete" && data.apiKey) {
        return data;
      }

      if (data.status === "expired") {
        throw new Error("Authorization expired. Please try again.");
      }

      if (data.status === "not_found") {
        throw new Error("Invalid authorization session. Please try again.");
      }
    } catch (err) {
      if (signal?.aborted) {
        throw new Error("Authorization cancelled", { cause: err });
      }
      if (err instanceof Error && err.message.includes("Please try again")) {
        throw err;
      }
      // Network glitch — retry
    }
  }

  throw new Error("Authorization timed out. Please try again.");
}
