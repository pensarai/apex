import type { HeaderRecord } from "./types";

export interface TargetHeaderProvider {
  readonly endpoint: string;
  readonly token: string;
}

export interface TargetHeaderSnapshot {
  readonly headers: HeaderRecord;
  readonly expiresAt: number;
}

// Self-contained because the browser MCP runs this closure in another process.
export function createTargetHeaderProvider(
  provider: TargetHeaderProvider,
  load: () => Promise<unknown> = async () => {
    const response = await fetch(provider.endpoint, {
      method: "POST",
      headers: { Authorization: `Bearer ${provider.token}` },
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error("Target credential refresh failed");
    }
    const body = await response.text();
    if (body.length > 65536)
      throw new Error("Target credential refresh failed");
    return JSON.parse(body);
  },
): () => Promise<HeaderRecord> {
  let cached: TargetHeaderSnapshot | undefined;
  let pending: Promise<HeaderRecord> | undefined;
  return async () => {
    if (cached && cached.expiresAt > Date.now()) return cached.headers;
    if (!pending) {
      pending = (async () => {
        try {
          const value = await load();
          if (!value || typeof value !== "object") throw new Error();
          if (JSON.stringify(value).length > 65536) throw new Error();
          const snapshot = value as TargetHeaderSnapshot;
          if (
            !Number.isSafeInteger(snapshot.expiresAt) ||
            snapshot.expiresAt <= Date.now() ||
            !snapshot.headers ||
            typeof snapshot.headers !== "object" ||
            Array.isArray(snapshot.headers) ||
            Object.entries(snapshot.headers).some(
              ([name, header]) =>
                !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) ||
                typeof header !== "string" ||
                /[\r\n\0]/.test(header),
            )
          ) {
            throw new Error();
          }
          cached = snapshot;
          return snapshot.headers;
        } catch {
          // Provider failures may contain auth material; never relay their text.
          throw new Error("Target credential refresh failed");
        } finally {
          pending = undefined;
        }
      })();
    }
    return pending;
  };
}

const providers = new WeakMap<
  TargetHeaderProvider,
  () => Promise<HeaderRecord>
>();

export function targetProviderHeaders(
  provider: TargetHeaderProvider,
): Promise<HeaderRecord> {
  let resolve = providers.get(provider);
  if (!resolve) {
    resolve = createTargetHeaderProvider(provider);
    providers.set(provider, resolve);
  }
  return resolve();
}
