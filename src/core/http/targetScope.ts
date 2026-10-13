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

export function isUrlInSessionScope(url: string, scope: TargetScope): boolean {
  const parsed = parseTargetUrl(url);
  return (
    parsed !== null &&
    isHostInScope(parsed.hostname, getSessionAllowedHosts(scope))
  );
}
