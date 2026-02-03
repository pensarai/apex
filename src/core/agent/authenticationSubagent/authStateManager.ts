/**
 * Authentication State Manager
 *
 * Central state management for authentication tokens, persistence, and export.
 * Handles token storage, expiration monitoring, and auth state sharing with other agents.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import type { Session } from "../../session";
import type {
  AuthState,
  AuthToken,
  AuthFlowDocumentation,
  ExportedAuthInfo,
  AuthStatus,
  RoleLevel,
  AuthEndpoint,
} from "./types";

const AUTH_DIR = "auth";
const AUTH_STATE_FILENAME = "auth-state.json";
const AUTH_FLOW_FILENAME = "auth-flow.json";

// Refresh tokens 5 minutes before expiration
const REFRESH_BUFFER_MS = 5 * 60 * 1000;

/**
 * Token Storage Interface
 */
interface TokenStorage {
  addToken(token: AuthToken): void;
  removeToken(name: string): void;
  getTokens(): AuthToken[];
}

/**
 * Auth Exporter Interface
 */
interface AuthExporter {
  getAuthHeaders(): Record<string, string>;
  getCookieString(): string;
  exportForAgent(): ExportedAuthInfo;
}

/**
 * Flow Documenter Interface
 */
interface FlowDocumenter {
  loadFlow(targetHost: string): AuthFlowDocumentation | null;
  saveFlow(flow: AuthFlowDocumentation): void;
}

/**
 * State change callback type
 */
type StateChangeCallback = (state: AuthState) => void;

/**
 * Generate a unique ID for auth state
 */
function generateAuthId(): string {
  return `auth_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
}

/**
 * AuthStateManager - Central auth state management
 *
 * Implements TokenStorage, AuthExporter, and FlowDocumenter interfaces.
 */
export class AuthStateManager implements TokenStorage, AuthExporter, FlowDocumenter {
  private state: AuthState;
  private authDir: string;
  private statePath: string;
  private flowPath: string;
  private refreshTimer?: ReturnType<typeof setTimeout>;
  private onStateChange?: StateChangeCallback;

  constructor(
    session: Session.SessionInfo,
    targetHost: string,
    onStateChange?: StateChangeCallback
  ) {
    this.onStateChange = onStateChange;

    // Create auth directory
    this.authDir = join(session.rootPath, AUTH_DIR);
    if (!existsSync(this.authDir)) {
      mkdirSync(this.authDir, { recursive: true });
    }

    this.statePath = join(this.authDir, AUTH_STATE_FILENAME);
    this.flowPath = join(this.authDir, AUTH_FLOW_FILENAME);

    // Initialize or load state
    this.state = this.loadOrCreateState(targetHost);
  }

  // ===========================================================================
  // State Management
  // ===========================================================================

  /**
   * Load existing state or create new state
   */
  private loadOrCreateState(targetHost: string): AuthState {
    if (existsSync(this.statePath)) {
      try {
        const data = readFileSync(this.statePath, "utf-8");
        const loaded = JSON.parse(data) as AuthState;
        // Verify it's for the same target
        if (loaded.targetHost === targetHost) {
          return loaded;
        }
      } catch {
        // Invalid file, create new
      }
    }

    return {
      id: generateAuthId(),
      targetHost,
      strategy: "provided",
      status: "pending",
      tokens: [],
    };
  }

  /**
   * Get current auth state (shallow copy)
   */
  getState(): AuthState {
    return { ...this.state };
  }

  /**
   * Update auth state with partial updates
   */
  updateState(updates: Partial<AuthState>): void {
    this.state = { ...this.state, ...updates };
    this.persist();
    this.notifyStateChange();
  }

  /**
   * Set auth status with valid transition check
   */
  setStatus(status: AuthStatus): void {
    // Valid transitions:
    // pending -> authenticating
    // authenticating -> active | failed
    // active -> expired | failed
    // expired -> authenticating
    // failed -> authenticating (retry)
    this.state.status = status;
    this.persist();
    this.notifyStateChange();
  }

  /**
   * Set endpoint configuration
   */
  setAuthEndpoint(endpoint: AuthEndpoint): void {
    this.state.authEndpoint = endpoint;
    this.persist();
  }

  /**
   * Set role level discovered during auth
   */
  setRoleLevel(role: RoleLevel): void {
    this.state.roleLevel = role;
    this.persist();
  }

  /**
   * Add discovered scopes
   */
  addDiscoveredScope(scope: string): void {
    if (!this.state.discoveredScopes) {
      this.state.discoveredScopes = [];
    }
    if (!this.state.discoveredScopes.includes(scope)) {
      this.state.discoveredScopes.push(scope);
      this.persist();
    }
  }

  // ===========================================================================
  // Token Storage Interface
  // ===========================================================================

  /**
   * Add a token, replacing existing token of same name
   */
  addToken(token: AuthToken): void {
    // Remove existing token of same name
    this.state.tokens = this.state.tokens.filter((t) => t.name !== token.name);
    this.state.tokens.push(token);
    this.state.status = "active";
    this.state.authenticatedAt = Date.now();
    this.persist();
    this.notifyStateChange();

    // Schedule refresh if token has expiration
    if (token.expiresAt) {
      this.scheduleRefresh(token);
    }
  }

  /**
   * Remove a token by name
   */
  removeToken(name: string): void {
    this.state.tokens = this.state.tokens.filter((t) => t.name !== name);
    if (this.state.tokens.length === 0) {
      this.state.status = "expired";
    }
    this.persist();
    this.notifyStateChange();
  }

  /**
   * Get all tokens
   */
  getTokens(): AuthToken[] {
    return [...this.state.tokens];
  }

  /**
   * Clear all tokens
   */
  clearTokens(): void {
    this.state.tokens = [];
    this.state.status = "expired";
    this.persist();
    this.notifyStateChange();
  }

  // ===========================================================================
  // Auth Exporter Interface
  // ===========================================================================

  /**
   * Get auth headers for HTTP requests
   */
  getAuthHeaders(): Record<string, string> {
    const headers: Record<string, string> = {};

    for (const token of this.state.tokens) {
      switch (token.type) {
        case "bearer":
        case "jwt":
          headers["Authorization"] = `Bearer ${token.value}`;
          break;
        case "api_key":
          // Use token name as header name (e.g., "X-API-Key")
          headers[token.name] = token.value;
          break;
        // Cookies handled separately via getCookieString()
      }
    }

    return headers;
  }

  /**
   * Get cookie string for HTTP requests
   */
  getCookieString(): string {
    const cookies = this.state.tokens
      .filter((t) => t.type === "cookie" || t.type === "session_id")
      .map((t) => `${t.name}=${t.value}`);
    return cookies.join("; ");
  }

  /**
   * Export auth info for use by other agents
   * Matches PentestTarget.authenticationInfo format
   */
  exportForAgent(): ExportedAuthInfo {
    const headers = this.getAuthHeaders();
    const cookies = this.getCookieString();

    return {
      method: this.detectMethodFromTokens(),
      details: this.generateAuthDetails(),
      cookies: cookies || undefined,
      headers:
        Object.entries(headers)
          .map(([k, v]) => `${k}: ${v}`)
          .join("; ") || undefined,
    };
  }

  /**
   * Export as curl flags for POC scripts
   */
  exportAsCurlFlags(): string {
    const parts: string[] = [];

    const headers = this.getAuthHeaders();
    for (const [name, value] of Object.entries(headers)) {
      parts.push(`-H "${name}: ${value}"`);
    }

    const cookies = this.getCookieString();
    if (cookies) {
      parts.push(`-b "${cookies}"`);
    }

    return parts.join(" ");
  }

  /**
   * Export as POC script snippet
   */
  exportAsPocScript(): string {
    const headers = this.getAuthHeaders();
    const cookies = this.getCookieString();

    let script = "#!/bin/bash\n\n# Authentication headers\n";

    for (const [name, value] of Object.entries(headers)) {
      script += `AUTH_HEADER_${name.toUpperCase().replace(/-/g, "_")}="${value}"\n`;
    }

    if (cookies) {
      script += `AUTH_COOKIES="${cookies}"\n`;
    }

    script += "\n# Example usage:\n";
    script += "# curl -H \"Authorization: $AUTH_HEADER_AUTHORIZATION\" -b \"$AUTH_COOKIES\" $TARGET_URL\n";

    return script;
  }

  // ===========================================================================
  // Flow Documenter Interface
  // ===========================================================================

  /**
   * Load documented auth flow for context recovery
   */
  loadFlow(targetHost: string): AuthFlowDocumentation | null {
    if (!existsSync(this.flowPath)) {
      return null;
    }

    try {
      const data = readFileSync(this.flowPath, "utf-8");
      const flow = JSON.parse(data) as AuthFlowDocumentation;

      // Verify it's for the same target
      if (flow.targetHost === targetHost) {
        return flow;
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Save auth flow documentation for future runs
   */
  saveFlow(flow: AuthFlowDocumentation): void {
    const flowWithTimestamp = {
      ...flow,
      documentedAt: Date.now(),
    };
    writeFileSync(this.flowPath, JSON.stringify(flowWithTimestamp, null, 2));
  }

  /**
   * Check if documented flow exists
   */
  hasDocumentedFlow(targetHost: string): boolean {
    return this.loadFlow(targetHost) !== null;
  }

  // ===========================================================================
  // Expiration Management
  // ===========================================================================

  /**
   * Check if any token is expired
   */
  isExpired(): boolean {
    if (this.state.status === "expired" || this.state.status === "failed") {
      return true;
    }

    const now = Date.now();
    for (const token of this.state.tokens) {
      if (token.expiresAt && token.expiresAt < now) {
        this.state.status = "expired";
        this.persist();
        return true;
      }
    }

    return false;
  }

  /**
   * Get time until next expiration (ms)
   */
  getTimeUntilExpiration(): number | null {
    const now = Date.now();
    let earliest: number | null = null;

    for (const token of this.state.tokens) {
      if (token.expiresAt) {
        const remaining = token.expiresAt - now;
        if (earliest === null || remaining < earliest) {
          earliest = remaining;
        }
      }
    }

    return earliest;
  }

  /**
   * Schedule token refresh before expiration
   */
  private scheduleRefresh(token: AuthToken): void {
    // Clear any existing timer
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }

    if (!token.expiresAt) return;

    // Calculate time until refresh (5 min before expiry)
    const refreshTime = token.expiresAt - Date.now() - REFRESH_BUFFER_MS;

    if (refreshTime > 0) {
      this.refreshTimer = setTimeout(() => {
        // Notify that refresh is needed
        this.state.status = "expired";
        this.notifyStateChange();
      }, refreshTime);
    }
  }

  /**
   * Mark last validation time
   */
  markValidated(): void {
    this.state.lastValidatedAt = Date.now();
    this.persist();
  }

  /**
   * Mark auth as failed
   */
  markFailed(error?: string): void {
    this.state.status = "failed";
    this.persist();
    this.notifyStateChange();
  }

  // ===========================================================================
  // Persistence
  // ===========================================================================

  /**
   * Persist state to file
   */
  private persist(): void {
    writeFileSync(this.statePath, JSON.stringify(this.state, null, 2));
  }

  /**
   * Notify state change callback
   */
  private notifyStateChange(): void {
    this.onStateChange?.(this.state);
  }

  // ===========================================================================
  // Helpers
  // ===========================================================================

  /**
   * Detect auth method from stored tokens
   */
  private detectMethodFromTokens(): string {
    const types = new Set(this.state.tokens.map((t) => t.type));

    if (types.has("jwt") || types.has("bearer")) {
      return "bearer";
    }
    if (types.has("api_key")) {
      return "api_key";
    }
    if (types.has("cookie") || types.has("session_id")) {
      return "cookie-based session";
    }
    return "unknown";
  }

  /**
   * Generate human-readable auth details
   */
  private generateAuthDetails(): string {
    if (!this.state.authEndpoint) {
      return "Include provided headers/cookies in requests";
    }

    return `${this.state.authEndpoint.method} ${this.state.authEndpoint.url}`;
  }

  // ===========================================================================
  // Cleanup
  // ===========================================================================

  /**
   * Clean up resources (timers, etc.)
   */
  cleanup(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = undefined;
    }
  }
}

// =============================================================================
// Pure Helper Functions
// =============================================================================

/**
 * Parse JWT token (base64 decode payload)
 */
export function parseJWT(token: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
} | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());

    return {
      header,
      payload,
      signature: parts[2],
    };
  } catch {
    return null;
  }
}

/**
 * Get JWT expiration time
 */
export function getJWTExpiration(token: string): number | null {
  const parsed = parseJWT(token);
  if (!parsed) return null;

  const exp = parsed.payload.exp as number | undefined;
  if (typeof exp !== "number") return null;

  // JWT exp is in seconds, convert to milliseconds
  return exp * 1000;
}

/**
 * Build auth headers from tokens
 */
export function buildAuthHeaders(tokens: AuthToken[]): Record<string, string> {
  const headers: Record<string, string> = {};

  for (const token of tokens) {
    switch (token.type) {
      case "bearer":
      case "jwt":
        headers["Authorization"] = `Bearer ${token.value}`;
        break;
      case "api_key":
        headers[token.name] = token.value;
        break;
    }
  }

  return headers;
}

/**
 * Format tokens as cookie string
 */
export function formatCookies(tokens: AuthToken[]): string {
  return tokens
    .filter((t) => t.type === "cookie" || t.type === "session_id")
    .map((t) => `${t.name}=${t.value}`)
    .join("; ");
}

/**
 * Extract cookies from Set-Cookie headers
 */
export function extractCookiesFromHeaders(
  headers: Record<string, string | string[]>
): AuthToken[] {
  const tokens: AuthToken[] = [];
  const setCookie = headers["set-cookie"] || headers["Set-Cookie"];

  if (!setCookie) return tokens;

  const cookieHeaders = Array.isArray(setCookie) ? setCookie : [setCookie];

  for (const header of cookieHeaders) {
    // Parse cookie: name=value; attributes...
    const parts = header.split(";");
    const [nameValue] = parts;
    if (!nameValue) continue;

    const eqIndex = nameValue.indexOf("=");
    if (eqIndex === -1) continue;

    const name = nameValue.substring(0, eqIndex).trim();
    const value = nameValue.substring(eqIndex + 1).trim();

    // Check for expiration
    let expiresAt: number | undefined;
    for (const part of parts.slice(1)) {
      const [attrName, attrValue] = part.split("=").map((s) => s.trim());
      if (attrName?.toLowerCase() === "expires" && attrValue) {
        const date = new Date(attrValue);
        if (!isNaN(date.getTime())) {
          expiresAt = date.getTime();
        }
      } else if (attrName?.toLowerCase() === "max-age" && attrValue) {
        const seconds = parseInt(attrValue, 10);
        if (!isNaN(seconds)) {
          expiresAt = Date.now() + seconds * 1000;
        }
      }
    }

    tokens.push({
      type: "cookie",
      name,
      value,
      expiresAt,
    });
  }

  return tokens;
}
