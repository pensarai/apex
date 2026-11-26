import { getDomain } from "tldts";
import { parseTargetUrl } from "../../util/url";

export interface TargetScope {
  readonly targets?: ReadonlyArray<string>;
  /**
   * Host-owned callback domains, already validated by
   * {@link normalizeCallbackDomains}. Reachable, never a target.
   */
  readonly callbackDomains?: ReadonlyArray<string>;
  readonly config?: {
    readonly scopeConstraints?: {
      readonly allowedHosts?: ReadonlyArray<string>;
      readonly allowedPorts?: ReadonlyArray<number>;
    };
  };
}

export function getRegistrableDomain(hostname: string): string {
  const lower = hostname.toLowerCase();
  return getDomain(lower, { allowPrivateDomains: false }) ?? lower;
}

export function getSessionAllowedHosts(scope: TargetScope): string[] {
  const hosts = new Set<string>();
  const explicit = scope.config?.scopeConstraints?.allowedHosts;
  for (const host of explicit ?? []) {
    const normalized = host.trim().toLowerCase().replace(/\.$/, "");
    if (normalized) hosts.add(normalized);
  }
  if (hosts.size > 0) return [...hosts];

  for (const target of scope.targets ?? []) {
    const parsed = parseTargetUrl(target);
    if (parsed) hosts.add(parsed.hostname.toLowerCase().replace(/\.$/, ""));
  }

  return [...hosts];
}

export function getSessionAllowedPorts(scope: TargetScope): number[] {
  return [
    ...new Set(
      (scope.config?.scopeConstraints?.allowedPorts ?? []).filter(
        (port) => Number.isInteger(port) && port >= 1 && port <= 65535,
      ),
    ),
  ];
}

export function isHostInScope(
  hostname: string,
  allowedHosts: ReadonlyArray<string>,
): boolean {
  const lower = hostname.toLowerCase().replace(/\.$/, "");
  return allowedHosts.some((allowed) => {
    const normalizedAllowed = allowed.toLowerCase().replace(/\.$/, "");
    const wildcard = normalizedAllowed.startsWith("*.");
    const base = wildcard ? normalizedAllowed.slice(2) : normalizedAllowed;
    return lower === base || (wildcard && lower.endsWith(`.${base}`));
  });
}

export function getUrlPort(url: string): number | null {
  let value = url.trim();
  if (!value) return null;
  if (!/^https?:\/\//i.test(value)) value = `https://${value}`;

  try {
    const parsed = new URL(value);
    if (parsed.protocol === "http:") {
      return parsed.port ? Number.parseInt(parsed.port, 10) : 80;
    }
    if (parsed.protocol === "https:") {
      return parsed.port ? Number.parseInt(parsed.port, 10) : 443;
    }
    return null;
  } catch {
    return null;
  }
}

export function isUrlInSessionScope(url: string, scope: TargetScope): boolean {
  const parsed = parseTargetUrl(url);
  const allowedPorts = getSessionAllowedPorts(scope);
  const port = getUrlPort(url);
  return (
    parsed !== null &&
    isHostInScope(parsed.hostname, getSessionAllowedHosts(scope)) &&
    (allowedPorts.length === 0 ||
      (port !== null && allowedPorts.includes(port)))
  );
}

// ---------------------------------------------------------------------------
// Callback domains: the one place their scope rules live
// ---------------------------------------------------------------------------

// A bare DNS name with an alphabetic TLD: no scheme, port, path, IP or wildcard.
const CALLBACK_HOSTNAME =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Validates and normalizes the callback domains a host supplies, once, where
 * they enter. A listed domain is exempt from target scope checks, so anything
 * that is not a bare hostname, or that is also a target or allowed host, is a
 * host configuration error and throws.
 */
export function normalizeCallbackDomains(
  domains: ReadonlyArray<string>,
  scope: TargetScope,
): string[] {
  const scopeHosts = [
    ...(scope.config?.scopeConstraints?.allowedHosts ?? []),
    ...(scope.targets ?? []).flatMap((target) => {
      const parsed = parseTargetUrl(target);
      return parsed ? [parsed.hostname] : [];
    }),
  ];
  const normalized = new Set<string>();
  for (const raw of domains) {
    const host = raw.trim().toLowerCase().replace(/\.$/, "");
    if (!CALLBACK_HOSTNAME.test(host)) {
      throw new Error(
        `Invalid callback domain "${raw}": expected a bare hostname, with no scheme, port, path, IP address or wildcard`,
      );
    }
    if (isHostInScope(host, scopeHosts)) {
      throw new Error(
        `Callback domain "${host}" is also a target or allowed host; callback domains must be separate from the target scope`,
      );
    }
    normalized.add(host);
  }
  return [...normalized];
}

export function isCallbackHost(hostname: string, scope: TargetScope): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return (scope.callbackDomains ?? []).includes(host);
}

/** Whether a request to `url` lands on one of the scope's callback domains. */
export function isCallbackDestination(
  url: string,
  scope: TargetScope,
): boolean {
  if (!scope.callbackDomains?.length) return false;
  try {
    return isCallbackHost(new URL(url).hostname, scope);
  } catch {
    return false;
  }
}

/** A target in scope, or a callback domain: the hosts a request may reach. */
export function isUrlReachable(url: string, scope: TargetScope): boolean {
  return isUrlInSessionScope(url, scope) || isCallbackDestination(url, scope);
}
