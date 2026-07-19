// Importing through the api barrel would cycle. Use the leaf constants
// module directly.
import { getPensarGatewayUrl } from "../api/constants";
import { config } from "../config";
import { ensureValidToken } from "./token";

export interface GatewayValidateResult {
  workspace: { name: string };
  credits: { balance: number };
  signingKey?: string;
  gatewayUrl?: string;
}

/**
 * Validate the current auth session against the Pensar Gateway and return
 * workspace + credit information.
 *
 * Resolves the gateway URL from config (server-issued) with a fallback to the
 * default gateway URL, obtains a valid token, and includes the workspace header
 * for all token types.
 *
 * If the response includes updated gateway config (signingKey / gatewayUrl),
 * persists them automatically.
 *
 * @returns null when the user is not authenticated.
 * @throws  on network / HTTP errors.
 */
export async function validateGateway(): Promise<GatewayValidateResult | null> {
  const cfg = await config.get();

  let tokenResult = await ensureValidToken({
    accessToken: cfg.accessToken,
    refreshToken: cfg.refreshToken,
    pensarAPIKey: cfg.pensarAPIKey,
    workosSession: cfg.workosSession,
    credentialBackend: cfg.credentialBackend,
  });

  if (!tokenResult) return null;

  const gatewayUrl = cfg.gatewayUrl || getPensarGatewayUrl();
  const sendRequest = (token: string) => {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
    };
    if (cfg.workspaceId) headers["X-Workspace-Id"] = cfg.workspaceId;
    return fetch(`${gatewayUrl}/gateway/validate`, {
      method: "GET",
      headers,
    });
  };

  let response = await sendRequest(tokenResult.token);
  if (response.status === 401 && tokenResult.type === "workos") {
    const refreshed = await ensureValidToken(
      {
        accessToken: cfg.accessToken,
        refreshToken: cfg.refreshToken,
        pensarAPIKey: cfg.pensarAPIKey,
        workosSession: cfg.workosSession,
        credentialBackend: cfg.credentialBackend,
      },
      { forceRefresh: true, rejectedToken: tokenResult.token },
    );
    if (!refreshed) return null;
    tokenResult = refreshed;
    response = await sendRequest(tokenResult.token);
  }

  if (!response.ok) {
    throw new Error(`Gateway validation failed (${response.status})`);
  }

  const result = (await response.json()) as GatewayValidateResult;

  if (result.signingKey || result.gatewayUrl) {
    await config.update({
      gatewaySigningKey: result.signingKey ?? undefined,
      gatewayUrl: result.gatewayUrl ?? undefined,
    });
  }

  return result;
}
