/**
 * Build Auth Config Utility
 *
 * Extracts the common authConfig construction pattern used by pentest.tsx
 * and operator-dashboard when calling agent APIs.
 */

import type { Config } from "../../core/config/config";
import type { AIAuthConfig } from "../../core/ai/utils";

/**
 * Build an AIAuthConfig from the app's Config object.
 *
 * Converts nullable config fields to undefined (as expected by AIAuthConfig)
 * and constructs the local model config when a localModelUrl is set.
 */
export function buildAuthConfig(config: Config): AIAuthConfig {
  return {
    anthropicAPIKey: config.anthropicAPIKey ?? undefined,
    openAiAPIKey: config.openAiAPIKey ?? undefined,
    openRouterAPIKey: config.openRouterAPIKey ?? undefined,
    local: config.localModelUrl ? { baseURL: config.localModelUrl } : undefined,
  };
}
