import {
  type ResolverSession,
  resolveEffectiveHeaders,
  stripBrowserManagedHeaders,
} from "../../../http/targetHeaders";
import {
  getSessionAllowedPorts,
  getSessionHeaderHosts,
  isUrlInHeaderScope,
} from "../../../http/targetScope";
import type { HeaderRecord } from "../../../http/types";

export interface BrowserHeaderPolicy {
  readonly allowedHosts: string[];
  readonly allowedPorts: number[];
  readonly headers: HeaderRecord;
}

export function resolveBrowserHeaderPolicy(
  session: ResolverSession,
  target?: string,
): BrowserHeaderPolicy {
  const targets = session.targets ?? [];
  const scopedSession =
    target && targets.length === 0
      ? { ...session, targets: [...targets, target] }
      : session;
  const allowedHosts = getSessionHeaderHosts(scopedSession);
  const allowedPorts = getSessionAllowedPorts(scopedSession);
  // The installed route gates injection per-request via allowedHosts, so the
  // snapshot must carry engagement headers even when the session starts on an
  // auxiliary host (e.g. a login/IdP). Resolve against any in-header-scope URL.
  const resolutionUrl = [target, ...(scopedSession.targets ?? [])].find(
    (candidate): candidate is string =>
      candidate !== undefined && isUrlInHeaderScope(candidate, scopedSession),
  );
  const headers = resolutionUrl
    ? stripBrowserManagedHeaders(
        resolveEffectiveHeaders(scopedSession, resolutionUrl),
      )
    : undefined;
  return {
    allowedHosts,
    allowedPorts,
    headers: headers ?? {},
  };
}

/** Adds engagement headers to in-scope page requests; navigation scope is the tool policy's job. */
export function browserHeaderRouteBody(policy: BrowserHeaderPolicy): string {
  return `
const __apexAllowedHosts = ${JSON.stringify(policy.allowedHosts)};
const __apexAllowedPorts = ${JSON.stringify(policy.allowedPorts)};
const __apexHeaders = ${JSON.stringify(policy.headers)};
if (Object.keys(__apexHeaders).length > 0) {
  await context.route('**/*', async route => {
    await route.continue();
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
