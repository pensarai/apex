import type { HeaderRecord } from "./types";

export const MAX_TARGET_REDIRECTS = 20;

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const BODY_HEADERS = new Set([
  "content-encoding",
  "content-language",
  "content-length",
  "content-location",
  "content-type",
  "transfer-encoding",
]);
const CROSS_ORIGIN_CREDENTIAL_HEADERS = new Set([
  "authorization",
  "cookie",
  "cookie2",
  "proxy-authorization",
]);

export interface RedirectHeaderContext {
  readonly crossOriginTainted: boolean;
  readonly bodyDropped: boolean;
}

export interface RedirectFetchResult {
  readonly response: Response;
  readonly redirectChain: string[];
}

export function redirectRequest<T>(
  status: number,
  method: string,
  body: T | undefined,
): { method: string; body: T | undefined; bodyDropped: boolean } {
  const normalizedMethod = method.toUpperCase();
  const rewritePost =
    (status === 301 || status === 302) && normalizedMethod === "POST";
  const rewriteNonGet =
    status === 303 && normalizedMethod !== "GET" && normalizedMethod !== "HEAD";
  if (rewritePost || rewriteNonGet) {
    return { method: "GET", body: undefined, bodyDropped: true };
  }
  return { method: normalizedMethod, body, bodyDropped: false };
}

export function isRedirectStatus(status: number): boolean {
  return REDIRECT_STATUSES.has(status);
}

export function resolveRedirectUrl(
  currentUrl: string,
  location: string,
): string {
  const next = new URL(location, currentUrl);
  if (next.protocol !== "http:" && next.protocol !== "https:") {
    throw new TypeError(`Unsupported redirect protocol: ${next.protocol}`);
  }
  return next.toString();
}

export function sanitizeRedirectHeaders(
  headers: HeaderRecord,
  context: RedirectHeaderContext,
): HeaderRecord {
  if (!context.crossOriginTainted && !context.bodyDropped) return headers;

  return Object.fromEntries(
    Object.entries(headers).filter(([name]) => {
      const normalized = name.toLowerCase();
      if (
        context.crossOriginTainted &&
        CROSS_ORIGIN_CREDENTIAL_HEADERS.has(normalized)
      ) {
        return false;
      }
      return !context.bodyDropped || !BODY_HEADERS.has(normalized);
    }),
  );
}

export async function fetchWithScopedRedirects(
  initialUrl: string,
  init: Omit<RequestInit, "headers">,
  headersForUrl: (url: string, context: RedirectHeaderContext) => HeaderRecord,
): Promise<RedirectFetchResult> {
  const redirectMode = init.redirect ?? "follow";
  let currentUrl = new URL(initialUrl).toString();
  let method = (init.method ?? "GET").toUpperCase();
  let body = init.body;
  let bodyDropped = false;
  let crossOriginTainted = false;
  const redirectChain = [currentUrl];

  for (let redirectCount = 0; ; redirectCount++) {
    const headers = sanitizeRedirectHeaders(
      headersForUrl(currentUrl, { crossOriginTainted, bodyDropped }),
      { crossOriginTainted, bodyDropped },
    );
    const response = await fetch(currentUrl, {
      ...init,
      method,
      body: body ?? undefined,
      headers,
      redirect: "manual",
    });

    const location = response.headers.get("location");
    if (!isRedirectStatus(response.status) || location === null) {
      return { response, redirectChain };
    }
    if (redirectMode === "manual") {
      return { response, redirectChain };
    }
    if (redirectMode === "error") {
      await response.body?.cancel();
      throw new TypeError("Redirect encountered while redirect mode is error");
    }
    if (redirectCount >= MAX_TARGET_REDIRECTS) {
      await response.body?.cancel();
      throw new TypeError(
        `Maximum redirect count exceeded (${MAX_TARGET_REDIRECTS})`,
      );
    }

    const nextUrl = resolveRedirectUrl(currentUrl, location);
    crossOriginTainted ||=
      new URL(currentUrl).origin !== new URL(nextUrl).origin;

    const redirectedRequest = redirectRequest(response.status, method, body);
    method = redirectedRequest.method;
    body = redirectedRequest.body;
    bodyDropped ||= redirectedRequest.bodyDropped;

    await response.body?.cancel();
    currentUrl = nextUrl;
    redirectChain.push(currentUrl);
  }
}
