import { getDomain } from "tldts";
import { parseTargetUrl } from "../../util/url";

export interface TargetScope {
  readonly targets?: ReadonlyArray<string>;
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
  // Match parseTargetUrl: keep any explicit scheme+authority so a connect://
  // target isn't rewritten to https://connect://… and mis-ported.
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = `https://${value}`;

  try {
    const parsed = new URL(value);
    if (parsed.port) return Number.parseInt(parsed.port, 10);
    // http is the only cleartext default; https and TLS-based transports
    // (connect/grpc/h2/ws over TLS) default to 443.
    return parsed.protocol === "http:" ? 80 : 443;
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
