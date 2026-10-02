/**
 * Transport seam for `sms_list_messages`.
 *
 * The default reads the stage-managed Mobile OTP number over the Console agent
 * API, which needs a sandbox (`AGENT_API_URL`). A host with direct database
 * access — the durable agent runtime — injects its own implementation instead,
 * the same way it injects a `SubagentSpawner`.
 */

export interface InboundSmsMessage {
  id: string;
  fromPhoneNumber: string;
  toPhoneNumber: string;
  body: string;
  /** ISO 8601. */
  receivedAt: string;
  /** ISO 8601, or null when still unconsumed. */
  consumedAt: string | null;
  code: string | null;
}

/** Conditions the tool reports back to the model rather than throwing on. */
export type SmsInboxRefusal =
  /** Another run holds the exclusive lease on the shared number. */
  | "lease-held"
  /** No Mobile OTP receiving number is configured for this workspace. */
  | "not-configured"
  /** The newest matching message was consumed by someone else first. */
  | "already-claimed";

export type SmsReserveResult =
  | { ok: true }
  | { ok: false; reason: SmsInboxRefusal };

export type SmsListResult =
  | {
      ok: true;
      messages: InboundSmsMessage[];
      claimed: InboundSmsMessage | null;
    }
  | { ok: false; reason: SmsInboxRefusal };

export interface SmsInbox {
  /**
   * Take the exclusive lease without reading, so the caller can trigger a
   * send-code with the number already reserved. The lease is time-bounded by
   * the host, so a reservation that is never followed by a list expires.
   */
  reserve(signal?: AbortSignal): Promise<SmsReserveResult>;

  /**
   * Read messages received at or after `sinceMs`. With `claim`, consumes the
   * newest unconsumed message so no other run can reuse that OTP. Releases the
   * lease before returning.
   */
  list(
    opts: { sinceMs: number; claim?: boolean },
    signal?: AbortSignal,
  ): Promise<SmsListResult>;
}

type SmsListResponse = {
  messages: InboundSmsMessage[];
  claimed: InboundSmsMessage | null;
};

function requireAgentApi(): { base: string; token: string } {
  const base = process.env.AGENT_API_URL;
  const token = process.env.AGENT_API_TOKEN;
  if (!base || !token) {
    throw new Error(
      "sms_list_messages requires AGENT_API_URL and AGENT_API_TOKEN (Console sandbox dispatch). Local CLI without Console cannot read inbound SMS.",
    );
  }
  return { base: base.replace(/\/+$/, ""), token };
}

function refusalForStatus(status: number): SmsInboxRefusal | null {
  if (status === 429) return "lease-held";
  if (status === 403) return "not-configured";
  if (status === 409) return "already-claimed";
  return null;
}

/** Reads inbound SMS over the Console agent API. Requires sandbox dispatch. */
export class HttpSmsInbox implements SmsInbox {
  private async get(
    params: URLSearchParams,
    signal?: AbortSignal,
  ): Promise<Response> {
    const { base, token } = requireAgentApi();
    const url = new URL(`${base}/agent/sms/messages`);
    url.search = params.toString();
    // biome-ignore lint/style/noRestrictedGlobals: Agent API (not the pentest target); must not pass through targetFetch.
    return fetch(url.toString(), {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
      signal,
    });
  }

  async reserve(signal?: AbortSignal): Promise<SmsReserveResult> {
    const res = await this.get(new URLSearchParams({ reserve: "1" }), signal);
    const refusal = refusalForStatus(res.status);
    if (refusal) return { ok: false, reason: refusal };
    if (!res.ok) {
      throw new Error(`SMS list API error ${res.status} ${res.statusText}`);
    }
    return { ok: true };
  }

  async list(
    opts: { sinceMs: number; claim?: boolean },
    signal?: AbortSignal,
  ): Promise<SmsListResult> {
    const params = new URLSearchParams({
      since: new Date(opts.sinceMs).toISOString(),
    });
    if (opts.claim) params.set("claim", "1");

    const res = await this.get(params, signal);
    const refusal = refusalForStatus(res.status);
    if (refusal) return { ok: false, reason: refusal };
    if (!res.ok) {
      throw new Error(`SMS list API error ${res.status} ${res.statusText}`);
    }
    const data = (await res.json()) as SmsListResponse;
    return { ok: true, messages: data.messages, claimed: data.claimed };
  }
}
