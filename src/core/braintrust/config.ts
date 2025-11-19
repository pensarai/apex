// Braintrust Configuration Management
//
// Handles initialization and caching of Braintrust configuration from the centralized config system.
// Uses a three-state cache (undefined/null/config) to distinguish between "not computed",
// "computed but disabled", and "computed and enabled" states.
//
// The configuration is sourced exclusively from ~/.pensar/config.json via the centralized config system.
// No environment variable fallbacks are used (following the repo pattern for optional integrations).

import type { BraintrustConfig } from './types';
import type { Config } from '../config/config';

// Three-state cache: undefined = not computed, null = disabled, object = enabled
let cachedConfig: BraintrustConfig | null | undefined = undefined;

// Retrieves and caches Braintrust configuration from the centralized config system.
// Returns null if Braintrust is disabled (no API key provided).
// Subsequent calls return the cached result.
export function getBraintrustConfig(config: Config): BraintrustConfig | null {
  // Return cached result if already computed
  if (cachedConfig !== undefined) {
    return cachedConfig;
  }

  const apiKey = config.braintrustAPIKey;

  // If no API key, disable
  if (!apiKey) {
    cachedConfig = null;
    return null;
  }

  // Use config values with defaults
  const environment = config.braintrustEnvironment || 'dev';

  cachedConfig = {
    apiKey,
    projectName: config.braintrustProjectName || 'apex-pentest',
    enabled: true,
    clientId: config.braintrustClientId || undefined,
    environment,
  };

  return cachedConfig;
}

// Checks if Braintrust integration is enabled.
// Returns true if configuration is valid and not explicitly disabled.
// This is a convenience wrapper around getBraintrustConfig() for boolean checks.
export function isBraintrustEnabled(config: Config): boolean {
  return getBraintrustConfig(config) !== null;
}
