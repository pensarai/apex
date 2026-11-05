import { AsyncLocalStorage } from "node:async_hooks";

/** One request a test domain received. */
export interface CallbackHit {
  id: string;
  receivedAt: string;
  method: string;
  /** Path and query, as received. */
  path: string;
  headers: Record<string, string>;
  sourceIp: string | null;
  bodyPreview: string;
  bodyTruncated: boolean;
  /** Arrived after the test domain was closed. */
  late: boolean;
}

export interface CallbackHits {
  /** Every stored hit, oldest first. */
  hits: CallbackHit[];
  /** Every request received, including ones past the host's storage cap. */
  totalHits: number;
}

/** The host could not answer. Never the same as "no callback arrived". */
export interface CallbackHitsUnavailable {
  state: "unavailable";
  reason: string;
}

/**
 * Reads what the session's `testDomains` received. The host that allocated
 * those domains supplies it; Apex never allocates or expires them.
 */
export interface CallbackHitReader {
  readHits(): Promise<CallbackHits | CallbackHitsUnavailable>;
}

const hitReader = new AsyncLocalStorage<CallbackHitReader>();

/**
 * `read_callback_hits` uses this reader for work run inside the scope,
 * including subagents it spawns.
 * @public
 */
export function withCallbackHitReader<T>(
  reader: CallbackHitReader,
  run: () => T,
): T {
  return hitReader.run(reader, run);
}

export function getCallbackHitReader(): CallbackHitReader | undefined {
  return hitReader.getStore();
}

export function sessionTestDomains(session: {
  config?: { testDomains?: readonly string[] };
}): string[] {
  return (session.config?.testDomains ?? [])
    .map((host) => host.trim().toLowerCase().replace(/\.$/, ""))
    .filter(Boolean);
}

export function isTestDomain(
  hostname: string,
  session: { config?: { testDomains?: readonly string[] } },
): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return sessionTestDomains(session).includes(host);
}
