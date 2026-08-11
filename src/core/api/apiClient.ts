/**
 * Shared HTTP client helpers for the Pensar Console REST API.
 *
 * Auth is handled via Bearer token (WorkOS JWT) or API key, with an
 * X-Workspace-Id header for JWT auth.
 */

import { ensureValidToken } from "../auth";
import { config } from "../config";
import { getPensarApiUrl } from "./constants";

async function getAuthHeaders(): Promise<Record<string, string>> {
  const cfg = await config.get();

  const validToken = await ensureValidToken({
    accessToken: cfg.accessToken,
    refreshToken: cfg.refreshToken,
    pensarAPIKey: cfg.pensarAPIKey,
  });

  if (!validToken) {
    throw new Error(
      "Not authenticated. Run `/login` in Apex or `pensar login` to reconnect to Pensar Console.",
    );
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${validToken.token}`,
  };

  if (cfg.workspaceId) {
    headers["X-Workspace-Id"] = cfg.workspaceId;
  }

  return headers;
}

export async function apiRequest<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const baseUrl = getPensarApiUrl();
  const headers = await getAuthHeaders();
  const url = `${baseUrl}${path}`;

  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }

  const response = await fetch(url, init);

  if (!response.ok) {
    const text = await response.text();
    let message: string;
    try {
      const err = JSON.parse(text) as { error?: string };
      message = err.error ?? text;
    } catch {
      message = text;
    }
    throw new Error(`API error (${response.status}): ${message}`);
  }

  // Some endpoints (e.g. 204-equivalent success responses) may return no body.
  const text = await response.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}
