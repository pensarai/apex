import {
  type ResolverSession,
  resolveEffectiveHeaders,
  stripBrowserManagedHeaders,
} from "../../../http/targetHeaders";
import {
  getSessionAllowedHosts,
  getSessionAllowedPorts,
} from "../../../http/targetScope";
import type { HeaderRecord } from "../../../http/types";

export interface BrowserHeaderPolicy {
  readonly allowedHosts: string[];
  readonly allowedPorts: number[];
  readonly headers: HeaderRecord;
  /** Abort off-scope page requests and redirects. Session policies leave this off. */
  readonly enforceScope: boolean;
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
  const allowedPorts = getSessionAllowedPorts(scopedSession);
  const headers =
    resolutionUrl && allowedHosts.length > 0
      ? stripBrowserManagedHeaders(
          resolveEffectiveHeaders(scopedSession, resolutionUrl),
        )
      : undefined;
  return {
    allowedHosts,
    allowedPorts,
    headers: headers ?? {},
    // Redirects and auth hops must load in the page; explicit navigations are
    // still held to the run's hosts by the tool policy.
    enforceScope: false,
  };
}

export function browserHeaderRouteBody(policy: BrowserHeaderPolicy): string {
  return `
const __apexAllowedHosts = ${JSON.stringify(policy.allowedHosts)};
const __apexAllowedPorts = ${JSON.stringify(policy.allowedPorts)};
const __apexHeaders = ${JSON.stringify(policy.headers)};
const __apexEnforceScope = ${JSON.stringify(policy.enforceScope)};
if (__apexEnforceScope || Object.keys(__apexHeaders).length > 0) {
  await context.route('**/*', async route => {
    if (__apexEnforceScope) await route.abort('blockedbyclient');
    else await route.continue();
  });
  await context.route(parsed => {
    const hostname = parsed.hostname.toLowerCase().replace(/\\.$/, '');
    const port = parsed.port
      ? Number(parsed.port)
      : parsed.protocol === 'http:'
        ? 80
        : parsed.protocol === 'https:'
          ? 443
          : undefined;
    const hostAllowed = __apexAllowedHosts.some(value => {
      const normalized = value.toLowerCase().replace(/\\.$/, '');
      const wildcard = normalized.startsWith('*.');
      const base = wildcard ? normalized.slice(2) : normalized;
      return hostname === base || (wildcard && hostname.endsWith('.' + base));
    });
    return hostAllowed &&
      (__apexAllowedPorts.length === 0 ||
        (port !== undefined && __apexAllowedPorts.includes(port)));
  }, async route => {
    const request = route.request();
    const requestHeaders = Object.fromEntries(
      Object.entries(await request.allHeaders()).filter(
        ([name]) => !name.startsWith(':'),
      ),
    );
    const response = await route.fetch({
      headers: { ...requestHeaders, ...__apexHeaders },
      maxRedirects: 0,
    });
    if (
      __apexEnforceScope &&
      [301, 302, 303, 307, 308].includes(response.status()) &&
      response.headers()['location']
    ) {
      await route.abort('blockedbyclient');
      return;
    }
    await route.fulfill({ response });
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
