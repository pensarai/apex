// Braintrust Client Management
//
// Manages singleton Braintrust logger instance with lazy initialization and error handling.
// Provides safe wrappers for client operations that gracefully handle failures without crashing.
//
// The logger is initialized on first access and cached for subsequent calls. If initialization
// fails, null is returned and warnings are logged (once per error type to avoid spam).

import { initLogger } from 'braintrust';
import { getBraintrustConfig } from './config';
import type { Config } from '../config/config';

// Braintrust logger type from SDK
type BraintrustLogger = ReturnType<typeof initLogger>;

// Three-state cache for logger: undefined = not initialized, null = init failed, object = initialized
let logger: BraintrustLogger | null | undefined;

// Separate warning flags to avoid silencing different error types
let initWarned = false;
let flushWarned = false;

// Retrieves or initializes the Braintrust logger instance.
// Returns null if configuration is disabled or initialization fails.
// Logs warnings on first failure only to avoid console spam.
export function getBraintrustLogger(config: Config): BraintrustLogger | null {
  if (logger !== undefined) {
    return logger;
  }

  const braintrustConfig = getBraintrustConfig(config);
  if (!braintrustConfig) {
    logger = null;
    return null;
  }

  try {
    logger = initLogger({
      apiKey: braintrustConfig.apiKey,
      projectName: braintrustConfig.projectName,
      asyncFlush: true, // Batches sends for efficiency
    });
  } catch (err) {
    if (!initWarned) {
      console.warn('[Braintrust] Failed to initialize logger, disabling tracing:', (err as Error).message);
      initWarned = true;
    }
    logger = null;
  }

  return logger;
}

// Safely flushes any pending Braintrust data with timeout.
// Gracefully handles errors to avoid crashing the application.
// Should be called at application shutdown or after critical operations.
export async function flushBraintrust(config: Config): Promise<void> {
  const l = getBraintrustLogger(config);
  if (!l) {
    return;
  }

  try {
    // Import flush dynamically to avoid issues if SDK not available
    const { flush } = await import('braintrust');
    await flush();
  } catch (err) {
    if (!flushWarned) {
      console.warn('[Braintrust] Flush failed, ignoring:', (err as Error).message);
      flushWarned = true;
    }
  }
}
