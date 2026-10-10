import { getDomain } from "tldts";
import { parseTargetUrl } from "../../util/url";

export interface TargetScope {
  readonly targets?: ReadonlyArray<string>;
  readonly config?: {
    readonly scopeConstraints?: {
      readonly allowedHosts?: ReadonlyArray<string>;
    };
  };
}

export function getRegistrableDomain(hostname: string): string {
  const lower = hostname.toLowerCase();
  return getDomain(lower, { allowPrivateDomains: false }) ?? lower;
}

export function getSessionAllowedHosts(scope: TargetScope): string[] {
  const hosts = new Set<string>();

  for (const target of scope.targets ?? []) {
    const parsed = parseTargetUrl(target);
    if (parsed) hosts.add(getRegistrableDomain(parsed.hostname));
  }

  for (const host of scope.config?.scopeConstraints?.allowedHosts ?? []) {
    hosts.add(host.toLowerCase());
  }

  return [...hosts];
}

export function isHostInScope(
  hostname: string,
  allowedHosts: ReadonlyArray<string>,
): boolean {
  const lower = hostname.toLowerCase();
  return allowedHosts.some((allowed) => {
    const normalizedAllowed = allowed.toLowerCase();
    return (
      lower === normalizedAllowed || lower.endsWith(`.${normalizedAllowed}`)
    );
  });
}

export function isUrlInSessionScope(
  url: string,
  scope: TargetScope,
): boolean {
  const parsed = parseTargetUrl(url);
  return (
    parsed !== null &&
    isHostInScope(parsed.hostname, getSessionAllowedHosts(scope))
  );
}
