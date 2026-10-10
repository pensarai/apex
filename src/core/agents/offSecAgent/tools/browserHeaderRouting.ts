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
const __apexRouteDebug = { invocations: 0, allowed: 0, rejected: 0, urlType: typeof URL, parseErrors: 0 };
context.__apexRouteDebug = __apexRouteDebug;
if (__apexAllowedHosts.length > 0 && Object.keys(__apexHeaders).length > 0) {
  await context.route('**/*', async route => {
    __apexRouteDebug.invocations++;
    const request = route.request();
    let allowed = false;
    try {
      const authority = request.url().match(/^[a-z][a-z\\d+.-]*:\\/\\/([^/?#]*)/i)?.[1];
      if (authority) {
        const hostPort = authority.slice(authority.lastIndexOf('@') + 1);
        const hostname = (hostPort.startsWith('[')
          ? hostPort.slice(0, hostPort.indexOf(']') + 1)
          : hostPort.split(':', 1)[0]
        ).toLowerCase();
        allowed = __apexAllowedHosts.some(value => {
          const allowedHost = value.toLowerCase();
          return hostname === allowedHost || hostname.endsWith('.' + allowedHost);
        });
      }
    } catch {
      __apexRouteDebug.parseErrors++;
      allowed = false;
    }
    if (!allowed) {
      __apexRouteDebug.rejected++;
      await route.continue();
      return;
    }
    __apexRouteDebug.allowed++;
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
  return { installed: true, urlType: typeof URL };
}`;
}
