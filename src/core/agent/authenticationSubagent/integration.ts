/**
 * Authentication Subagent Integration
 *
 * Integration utilities for using the authentication subagent with the
 * attack surface agent and orchestrator.
 */

import type { AIModel } from "../../ai";
import type { Session } from "../../session";
import { runAuthenticationSubagent } from "./agent";
import { AuthStateManager } from "./authStateManager";
import type {
  AuthenticationSubagentInput,
  AuthenticationSubagentResult,
  AuthCredentials,
  AuthFlowHints,
  ExportedAuthInfo,
} from "./types";

// =============================================================================
// Types
// =============================================================================

export interface AuthenticationConfig {
  target: string;
  session: Session.SessionInfo;
  credentials?: AuthCredentials;
  authFlowHints?: AuthFlowHints;
}

export interface EnsureAuthenticatedOptions {
  config: AuthenticationConfig;
  model: AIModel;
  forceRefresh?: boolean;
  abortSignal?: AbortSignal;
}

export interface EnsureAuthenticatedResult {
  success: boolean;
  authInfo?: ExportedAuthInfo;
  headers?: Record<string, string>;
  cookies?: string;
  error?: string;
  authBarrier?: {
    type: string;
    details: string;
  };
}

// =============================================================================
// Main Integration Function
// =============================================================================

/**
 * Ensure authentication is valid for a target.
 *
 * This function checks if there's existing valid auth, and if not,
 * runs the auth subagent to acquire new credentials.
 *
 * Use this in the orchestrator before spawning test agents.
 */
export async function ensureAuthenticated(
  opts: EnsureAuthenticatedOptions
): Promise<EnsureAuthenticatedResult> {
  const { config, model, forceRefresh = false, abortSignal } = opts;
  const { target, session, credentials, authFlowHints } = config;

  // Extract host from target
  const targetHost = extractHost(target);

  // Check existing auth state
  const authStateManager = new AuthStateManager(session, targetHost);
  const existingState = authStateManager.getState();

  // If we have valid auth and not forcing refresh, use existing
  if (!forceRefresh && existingState.status === "active" && !authStateManager.isExpired()) {
    return {
      success: true,
      authInfo: authStateManager.exportForAgent(),
      headers: authStateManager.getAuthHeaders(),
      cookies: authStateManager.getCookieString() || undefined,
    };
  }

  // Check if we have tokens to verify
  const hasTokensToVerify = credentials?.tokens && (
    credentials.tokens.bearerToken ||
    credentials.tokens.cookies ||
    credentials.tokens.sessionToken ||
    (credentials.tokens.customHeaders && Object.keys(credentials.tokens.customHeaders).length > 0)
  );

  // No valid auth or forcing refresh - run auth subagent
  if (!credentials?.username && !credentials?.apiKey && !hasTokensToVerify) {
    // No credentials or tokens provided, can't authenticate
    return {
      success: false,
      error: "No credentials or tokens provided for authentication",
    };
  }

  try {
    const result = await runAuthenticationSubagent({
      input: {
        target,
        session,
        credentials,
        authFlowHints,
      },
      model,
      abortSignal,
      enableBrowserTools: true,
    });

    if (result.success) {
      return {
        success: true,
        authInfo: authStateManager.exportForAgent(),
        headers: result.exportedHeaders,
        cookies: result.exportedCookies,
      };
    } else {
      return {
        success: false,
        error: result.summary,
        authBarrier: result.authBarrier,
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    authStateManager.cleanup();
  }
}

/**
 * Quick auth validation - checks if existing auth is still valid.
 *
 * Does NOT run the auth subagent, just checks existing state.
 * Use this for quick checks without the overhead of running the agent.
 */
export function checkAuthStatus(
  session: Session.SessionInfo,
  target: string
): { valid: boolean; needsRefresh: boolean; status: string } {
  const targetHost = extractHost(target);
  const authStateManager = new AuthStateManager(session, targetHost);
  const state = authStateManager.getState();

  const isExpired = authStateManager.isExpired();
  const valid = state.status === "active" && !isExpired;
  const needsRefresh = isExpired || state.status === "expired";

  authStateManager.cleanup();

  return {
    valid,
    needsRefresh,
    status: state.status,
  };
}

/**
 * Get existing auth info without running the agent.
 *
 * Returns auth headers/cookies if available, or undefined if not.
 */
export function getExistingAuth(
  session: Session.SessionInfo,
  target: string
): ExportedAuthInfo | undefined {
  const targetHost = extractHost(target);
  const authStateManager = new AuthStateManager(session, targetHost);
  const state = authStateManager.getState();

  if (state.status !== "active" || authStateManager.isExpired()) {
    authStateManager.cleanup();
    return undefined;
  }

  const authInfo = authStateManager.exportForAgent();
  authStateManager.cleanup();

  return authInfo;
}

/**
 * Build authentication info for PentestTarget from auth state.
 *
 * Use this to convert auth subagent results to the format expected
 * by the orchestrator and test agents.
 */
export function buildTargetAuthInfo(
  result: AuthenticationSubagentResult
): { method: string; details: string; cookies?: string; headers?: string } | undefined {
  if (!result.success) {
    return undefined;
  }

  const authInfo: { method: string; details: string; cookies?: string; headers?: string } = {
    method: result.authState.tokens.length > 0
      ? result.authState.tokens[0].type
      : "unknown",
    details: result.summary,
  };

  if (result.exportedCookies) {
    authInfo.cookies = result.exportedCookies;
  }

  if (result.exportedHeaders && Object.keys(result.exportedHeaders).length > 0) {
    authInfo.headers = Object.entries(result.exportedHeaders)
      .map(([k, v]) => `${k}: ${v}`)
      .join("; ");
  }

  return authInfo;
}

// =============================================================================
// Helpers
// =============================================================================

function extractHost(target: string): string {
  try {
    const url = new URL(target);
    return url.host;
  } catch {
    return target;
  }
}
