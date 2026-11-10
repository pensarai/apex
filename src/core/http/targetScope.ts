import { getDomain } from "tldts";
import { parseTargetUrl } from "../../util/url";

export interface TargetScope {
  readonly targets?: ReadonlyArray<string>;
  readonly config?: {
    readonly scopeConstraints?: {
      readonly allowedHosts?: ReadonlyArray<string>;
      readonly allowedPorts?: ReadonlyArray<number>;
      readonly identityProviderHosts?: ReadonlyArray<string>;
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

/**
 * Whether `url` is an HTTPS page on one of the host-supplied identity provider
 * hosts. Exact hostnames only: these hosts are reachable by browser navigation
 * for sign-in, but are never targets and never receive session headers.
 */
export function isIdentityProviderNavigation(
  url: string,
  scope: TargetScope,
): boolean {
  const hosts = scope.config?.scopeConstraints?.identityProviderHosts ?? [];
  if (hosts.length === 0) return false;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:" || parsed.port !== "") return false;
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
  return hosts.some((host) => host.trim().toLowerCase() === hostname);
}
