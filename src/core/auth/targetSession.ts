export type BrowserStorageCookie = {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires?: number;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "Strict" | "Lax" | "None";
};

export type BrowserStorageState = {
  cookies: BrowserStorageCookie[];
  origins: Array<{
    origin: string;
    localStorage: Array<{ name: string; value: string }>;
  }>;
};

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  hostnameOf,
  isGoogleTransitHost,
  isIssuerTransitHost,
} from "./transit";

export function filterMixedDomainState(
  state: BrowserStorageState,
  opts: { targetOrigin: string; issuerUrl?: string },
): BrowserStorageState {
  const targetHost =
    hostnameOf(opts.targetOrigin) ?? opts.targetOrigin.toLowerCase();
  const issuerHost = opts.issuerUrl ? hostnameOf(opts.issuerUrl) : null;

  const cookies = state.cookies.filter((cookie) => {
    const domain = cookie.domain.replace(/^\./, "").toLowerCase();
    if (isGoogleTransitHost(domain)) return false;
    if (issuerHost && isIssuerTransitHost(domain, opts.issuerUrl)) return false;
    return (
      domain === targetHost ||
      targetHost.endsWith(`.${domain}`) ||
      domain.endsWith(`.${targetHost}`)
    );
  });

  const origins = state.origins.filter((origin) => {
    const host = hostnameOf(origin.origin);
    if (!host) return false;
    if (isGoogleTransitHost(host)) return false;
    if (issuerHost && isIssuerTransitHost(host, opts.issuerUrl)) return false;
    return origin.origin === opts.targetOrigin || host === targetHost;
  });

  return { cookies, origins };
}

export function cookieHeaderFromState(state: BrowserStorageState): string {
  return state.cookies
    .map((cookie) => `${cookie.name}=${cookie.value}`)
    .join("; ");
}

export function loadPersistedTargetHeaders(
  sessionRootPath: string,
): Record<string, string> {
  const path = join(sessionRootPath, "auth", "target-session.json");
  try {
    if (!existsSync(path)) return {};
    const parsed = JSON.parse(readFileSync(path, "utf-8")) as {
      cookies?: string;
      headers?: Record<string, string>;
    };
    const headers: Record<string, string> = { ...(parsed.headers ?? {}) };
    if (parsed.cookies) headers.Cookie = parsed.cookies;
    return headers;
  } catch {
    return {};
  }
}

export function opaqueAuthHandle(): string {
  return `auth_${crypto.randomUUID().replace(/-/g, "")}`;
}
