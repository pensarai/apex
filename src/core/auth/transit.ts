import { getDomain } from "tldts";

const GOOGLE_HOST_SUFFIXES = [
  "google.com",
  "googleusercontent.com",
  "gstatic.com",
  "googleapis.com",
  "ggpht.com",
  "youtube.com",
  "g.co",
  "accounts.google.com",
];

export type TransitKind = "google" | "issuer" | "target";

export function hostnameOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function isGoogleTransitHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return GOOGLE_HOST_SUFFIXES.some(
    (suffix) => host === suffix || host.endsWith(`.${suffix}`),
  );
}

export function isIssuerTransitHost(
  hostname: string,
  issuerUrl?: string,
): boolean {
  if (!issuerUrl) return false;
  const issuerHost = hostnameOf(issuerUrl);
  return Boolean(issuerHost && hostname.toLowerCase() === issuerHost);
}

export function classifyOrigin(
  url: string,
  opts?: { issuerUrl?: string },
): TransitKind {
  const host = hostnameOf(url);
  if (!host) return "target";
  if (isIssuerTransitHost(host, opts?.issuerUrl)) return "issuer";
  if (isGoogleTransitHost(host)) return "google";
  return "target";
}

export function isAuthTransitUrl(
  url: string,
  opts?: { issuerUrl?: string },
): boolean {
  const kind = classifyOrigin(url, opts);
  return kind === "google" || kind === "issuer";
}

export function transitToolAllowed(
  toolName: string,
  url: string,
  opts?: { issuerUrl?: string },
): boolean {
  if (!isAuthTransitUrl(url, opts)) return true;
  return (
    toolName === "browser_snapshot" ||
    toolName === "browser_tabs" ||
    toolName === "browser_navigate" ||
    toolName === "complete_authentication"
  );
}

export function registrableDomain(hostname: string): string {
  const lower = hostname.toLowerCase();
  return getDomain(lower, { allowPrivateDomains: false }) ?? lower;
}
