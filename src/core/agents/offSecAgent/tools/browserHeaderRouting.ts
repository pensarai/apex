import {
  createTargetHeaderProvider,
  type TargetHeaderProvider,
} from "../../../http/targetHeaderProvider";
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
  readonly targetHeaderProvider?: TargetHeaderProvider;
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
  return {
    allowedHosts,
    headers: headers ?? {},
    ...(session.config?.targetHeaderProvider
      ? { targetHeaderProvider: session.config.targetHeaderProvider }
      : {}),
  };
}

export function browserHeaderRouteBody(policy: BrowserHeaderPolicy): string {
  return `
const __apexAllowedHosts = ${JSON.stringify(policy.allowedHosts)};
const __apexHeaders = ${JSON.stringify(policy.headers)};
const __apexProvider = ${JSON.stringify(policy.targetHeaderProvider ?? null)};
const __apexGetHeaders = __apexProvider
  ? (${createTargetHeaderProvider.toString()})(__apexProvider, async () => {
      const response = await context.request.post(__apexProvider.endpoint, {
        headers: { Authorization: 'Bearer ' + __apexProvider.token },
        maxRedirects: 0,
        timeout: 15000,
      });
      try {
        if (!response.ok()) throw new Error('Target credential refresh failed');
        const body = await response.text();
        if (body.length > 65536) throw new Error('Target credential refresh failed');
        return JSON.parse(body);
      } finally {
        await response.dispose();
      }
    })
  : null;
const __apexManagedNames = new Set(Object.keys(__apexHeaders).map(name => name.toLowerCase()));
if (__apexAllowedHosts.length > 0 && (Object.keys(__apexHeaders).length > 0 || __apexGetHeaders)) {
  await context.route('**/*', async route => {
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
      allowed = false;
    }
    if (!allowed) {
      if (__apexGetHeaders) {
        const headers = await request.allHeaders();
        const filtered = Object.fromEntries(Object.entries(headers).filter(
          ([name]) => !name.startsWith(':') && !__apexManagedNames.has(name.toLowerCase()),
        ));
        await route.continue({ headers: filtered });
      } else {
        await route.continue();
      }
      return;
    }
    let currentHeaders = __apexHeaders;
    if (__apexGetHeaders) {
      try {
        const fresh = Object.fromEntries(Object.entries(await __apexGetHeaders()).filter(
          ([name]) => name.toLowerCase() !== 'user-agent',
        ));
        currentHeaders = Object.fromEntries(Object.entries(__apexHeaders).filter(
          ([name]) => !Object.keys(fresh).some(key => key.toLowerCase() === name.toLowerCase()),
        ));
        Object.assign(currentHeaders, fresh);
        for (const name of Object.keys(currentHeaders)) __apexManagedNames.add(name.toLowerCase());
      } catch {
        await route.abort('failed');
        return;
      }
    }
    const requestHeaders = Object.fromEntries(
      Object.entries(await request.allHeaders()).filter(
        ([name]) => !name.startsWith(':') && !__apexManagedNames.has(name.toLowerCase()),
      ),
    );
    const headers = { ...requestHeaders, ...currentHeaders };
    if (__apexGetHeaders) {
      try {
        const response = await route.fetch({ headers, maxRedirects: 0 });
        try {
          await route.fulfill({ response });
        } finally {
          await response.dispose();
        }
      } catch {
        await route.abort('failed');
      }
    } else {
      await route.continue({ headers });
    }
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
