import type { Config } from "../config/config";
import type { AIAuthConfig } from "./utils";

/**
 * Build an AIAuthConfig from the user's saved config.
 *
 * This bridges the gap between config.json (where keys like pensarAPIKey
 * are stored via /auth) and the AIAuthConfig that getProviderModel() uses.
 * Without this, providers whose keys live only in config.json (not env vars)
 * never receive their credentials.
 */
export function buildAuthConfig(config: Config): AIAuthConfig {
  return {
    openAiAPIKey: config.openAiAPIKey ?? undefined,
    anthropicAPIKey: config.anthropicAPIKey ?? undefined,
    openRouterAPIKey: config.openRouterAPIKey ?? undefined,
    pensarAPIKey: config.pensarAPIKey ?? undefined,
    pensarApiUrl: config.pensarApiUrl ?? undefined,
  };
}
