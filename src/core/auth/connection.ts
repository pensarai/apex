import { config } from "../config";

/**
 * Check whether the user is connected to Pensar Console
 * (either via WorkOS tokens or a legacy API key).
 */
export function isConnected(cfg: {
  accessToken?: string | null;
  pensarAPIKey?: string | null;
}): boolean {
  return !!(cfg.accessToken || cfg.pensarAPIKey);
}

/**
 * Disconnect from Pensar Console by clearing all auth fields in the config.
 */
export async function disconnect(): Promise<void> {
  await config.update({
    pensarAPIKey: null,
    accessToken: null,
    refreshToken: null,
    workspaceId: null,
    workspaceSlug: null,
    gatewaySigningKey: null,
  });
}
