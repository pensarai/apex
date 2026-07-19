import { config } from "../config";
import { clearWorkOSSession } from "./token";

/**
 * Check whether the user is connected to Pensar Console
 * (either via WorkOS tokens or a legacy API key).
 */
export function isConnected(cfg: {
  accessToken?: string | null;
  pensarAPIKey?: string | null;
  refreshToken?: string | null;
  workosSession?: boolean;
}): boolean {
  return !!(
    cfg.workosSession ||
    cfg.refreshToken ||
    cfg.accessToken ||
    cfg.pensarAPIKey
  );
}

/**
 * Disconnect from Pensar Console by clearing all auth fields in the config.
 */
export async function disconnect(): Promise<void> {
  await clearWorkOSSession();
  await config.update({
    pensarAPIKey: null,
    workspaceId: null,
    workspaceSlug: null,
    gatewaySigningKey: null,
    gatewayUrl: null,
  });
}
