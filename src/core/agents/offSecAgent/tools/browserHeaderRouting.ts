import {
  type ResolverSession,
  resolveEffectiveHeaders,
  stripBrowserManagedHeaders,
} from "../../../http/targetHeaders";
import { getSessionAllowedHosts } from "../../../http/targetScope";
import type { HeaderRecord } from "../../../http/types";

export interface BrowserHeaderPolicy {
  readonly allowedHosts: string[];
  readonly headers: HeaderRecord;
}

export function resolveBrowserHeaderPolicy(
  session: ResolverSession,
  target?: string,
): BrowserHeaderPolicy {
  const targets = session.targets ?? [];
  const scopedSession =
    target && !targets.includes(target)
      ? { ...session, targets: [...targets, target] }
      : session;
  const resolutionUrl = target ?? scopedSession.targets?.[0];
  const allowedHosts = getSessionAllowedHosts(scopedSession);
  const headers =
    resolutionUrl && allowedHosts.length > 0
      ? stripBrowserManagedHeaders(
          resolveEffectiveHeaders(scopedSession, resolutionUrl),
        )
      : undefined;
  return { allowedHosts, headers: headers ?? {} };
}

export function browserHeaderRouteBody(policy: BrowserHeaderPolicy): string {
  return `
const __apexAllowedHosts = ${JSON.stringify(policy.allowedHosts)};
const __apexHeaders = ${JSON.stringify(policy.headers)};
if (__apexAllowedHosts.length > 0 && Object.keys(__apexHeaders).length > 0) {
  await context.route('**/*', async route => {
    const request = route.request();
    let allowed = false;
    try {
      const hostname = new URL(request.url()).hostname.toLowerCase();
      allowed = __apexAllowedHosts.some(value => {
        const allowedHost = value.toLowerCase();
        return hostname === allowedHost || hostname.endsWith('.' + allowedHost);
      });
    } catch {
      allowed = false;
    }
    if (!allowed) {
      await route.continue();
      return;
    }
    const requestHeaders = await request.allHeaders();
    await route.continue({ headers: { ...requestHeaders, ...__apexHeaders } });
  });
}
`;
}

export function browserHeaderRouteFunction(
  policy: BrowserHeaderPolicy,
): string {
  return `async (page) => {
  const context = page.context();
  ${browserHeaderRouteBody(policy)}
  return { installed: true };
}`;
}
