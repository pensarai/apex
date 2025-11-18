// Braintrust Configuration Management
//
// Handles initialization and caching of Braintrust configuration from environment variables.
// Uses a three-state cache (undefined/null/config) to distinguish between "not computed",
// "computed but disabled", and "computed and enabled" states, avoiding repeated env var reads.
//
// Environment Variables:
// - BRAINTRUST_API_KEY: Required API key for Braintrust authentication
// - BRAINTRUST_ENABLED: Set to 'false' to explicitly disable even with valid API key
// - BRAINTRUST_PROJECT_NAME: Optional project name (defaults to 'apex-pentest')
// - BRAINTRUST_CLIENT_ID: Optional client identifier for multi-client scenarios
// - BRAINTRUST_ENVIRONMENT: Optional environment tag ('dev', 'staging', 'prod')

import type { BraintrustConfig } from './types';

// Three-state cache: undefined = not computed, null = disabled, object = enabled
let cachedConfig: BraintrustConfig | null | undefined = undefined;

// Retrieves and caches Braintrust configuration from environment variables.
// Returns null if Braintrust is disabled (no API key or explicitly disabled).
// Subsequent calls return the cached result without re-reading environment variables.
export function getBraintrustConfig(): BraintrustConfig | null {
  // Return cached result if already computed
  if (cachedConfig !== undefined) {
    return cachedConfig;
  }

  const apiKey = process.env.BRAINTRUST_API_KEY;

  // If no API key, disable
  if (!apiKey) {
    cachedConfig = null;
    return null;
  }

  // Check explicit disable flag
  const explicitlyDisabled = process.env.BRAINTRUST_ENABLED === 'false';
  if (explicitlyDisabled) {
    cachedConfig = null;
    return null;
  }

  // Validate environment value before casting
  const envValue = process.env.BRAINTRUST_ENVIRONMENT;
  const validEnvironments = ['dev', 'staging', 'prod'] as const;
  const environment: BraintrustConfig['environment'] =
    envValue && validEnvironments.includes(envValue as any)
      ? (envValue as BraintrustConfig['environment'])
      : 'dev';

  cachedConfig = {
    apiKey,
    projectName: process.env.BRAINTRUST_PROJECT_NAME || 'apex-pentest',
    enabled: true,
    clientId: process.env.BRAINTRUST_CLIENT_ID,
    environment,
  };

  return cachedConfig;
}

// Checks if Braintrust integration is enabled.
// Returns true if configuration is valid and not explicitly disabled.
// This is a convenience wrapper around getBraintrustConfig() for boolean checks.
export function isBraintrustEnabled(): boolean {
  return getBraintrustConfig() !== null;
}
