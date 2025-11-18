// Braintrust Client Management
//
// Manages singleton Braintrust SDK client instance with lazy initialization and error handling.
// Provides safe wrappers for client operations that gracefully handle failures without crashing.
//
// The client is initialized on first access and cached for subsequent calls. If initialization
// fails, null is returned and warnings are logged (once per error type to avoid spam).
//
// TODO: Replace placeholder types and initialization with real Braintrust SDK once integrated.

import { get } from '../config/config';
import { getBraintrustConfig } from './config';
import type { BraintrustConfig } from './types';
// import { Braintrust } from 'braintrust'; // or whatever the SDK exposes

type BraintrustClient = any; // tighten once you wire the SDK

// Three-state cache for client: undefined = not initialized, null = init failed, object = initialized
let client: BraintrustClient | null | undefined;

// Separate warning flags to avoid silencing different error types
let initWarned = false;
let flushWarned = false;

// Retrieves or initializes the Braintrust client instance.
// Returns null if configuration is disabled or initialization fails.
// Logs warnings on first failure only to avoid console spam.
export function getBraintrustClient(): BraintrustClient | null {
  if (client !== undefined) return client;

  const config = getBraintrustConfig();
  if (!config) {
    client = null;
    return null;
  }

  try {
    // TODO: replace with real Braintrust SDK init
    // client = new Braintrust({ apiKey: config.apiKey, projectName: config.projectName, ... });
    client = {}; // placeholder so you can wire tracer.ts without import errors
  } catch (err) {
    if (!initWarned) {
      console.warn('[Braintrust] Failed to initialize client, disabling tracing:', (err as Error).message);
      initWarned = true;
    }
    client = null;
  }

  return client;
}

// Safely flushes any pending Braintrust data with timeout.
// Gracefully handles errors to avoid crashing the application.
// Should be called at application shutdown or after critical operations.
export async function safeFlush(): Promise<void> {
  const c = getBraintrustClient();
  if (!c) return;

  try {
    // TODO: Implement actual flush once SDK is integrated
    // await c.flush({ timeoutMs: 3000 });
  } catch (err) {
    if (!flushWarned) {
      console.warn('[Braintrust] Flush failed, ignoring:', (err as Error).message);
      flushWarned = true;
    }
  }
}

