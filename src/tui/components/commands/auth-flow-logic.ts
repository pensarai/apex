import { ensureValidToken } from "../../../core/auth";
import type { Config } from "../../../core/config/config";

type StoredAuthConfig = Pick<
  Config,
  "accessToken" | "refreshToken" | "pensarAPIKey" | "workspaceId"
>;

export type StoredAuthResolution =
  | { status: "connected" }
  | { status: "reauthenticate" }
  | { status: "select-workspace"; accessToken: string };

export async function resolveStoredAuth(
  config: StoredAuthConfig,
): Promise<StoredAuthResolution> {
  const validToken = await ensureValidToken({
    accessToken: config.accessToken,
    refreshToken: config.refreshToken,
    pensarAPIKey: config.pensarAPIKey,
  });

  if (!validToken) return { status: "reauthenticate" };

  if (validToken.type === "workos" && !config.workspaceId) {
    return { status: "select-workspace", accessToken: validToken.token };
  }

  return { status: "connected" };
}
