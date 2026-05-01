/**
 * Tier-1 instrumentation for diagnosing LLM-call stalls in production.
 *
 * Provides:
 *  - `logEvent`: structured stdout log emitter, always-on (ignores `silent`).
 *  - `newCallId`: short opaque ID for joining log lines for a single fetch.
 *  - `wrapFetchWithBedrockLogs`: instruments any `fetch` with start / headers /
 *    first-byte / done / error / signal-abort events. Preserves backpressure.
 *
 * Why a separate channel:
 *   The CLI/TUI uses `silent: true` to suppress noisy retry warnings from the
 *   user's terminal. In server contexts (recon service) those warnings are
 *   the primary signal for diagnosing multi-hour stalls — they were silenced
 *   too. This module emits structured logs that bypass `silent` so they always
 *   reach CloudWatch via the awslogs driver.
 *
 * Log shape:
 *   `[apex.instrumentation] { "event": "...", "ts": <ms>, ... }`
 *   The literal prefix is greppable and CloudWatch Insights can parse the
 *   trailing JSON with `parse @message "[apex.instrumentation] *" as raw`.
 */

let counter = 0;

/** Short opaque ID for correlating log entries for one fetch / call. */
export function newCallId(): string {
  // 8-char base36; not cryptographic — just for log correlation.
  counter = (counter + 1) >>> 0;
  return (
    Date.now().toString(36).slice(-4) +
    counter.toString(36).padStart(4, "0").slice(-4)
  );
}

/**
 * Emit a structured log line. Always written to stdout regardless of any
 * `silent` flag. Never throws — logging must not break the request path.
 */
export function logEvent(
  event: string,
  payload: Record<string, unknown> = {},
): void {
  try {
    console.log(
      `[apex.instrumentation] ${JSON.stringify({ event, ts: Date.now(), ...payload })}`,
    );
  } catch {
    // never let logging break a request
  }
}

/**
 * Wrap a fetch implementation with per-request lifecycle logging.
 *
 * Each fetch invocation gets a unique `callId`; subsequent log entries for the
 * same fetch share that ID. Body is wrapped in a passthrough `ReadableStream`
 * with `pull` semantics so backpressure from downstream consumers is preserved.
 *
 * Events emitted (each with `callId`, `ts`, and `ageMs` since fetch start):
 *  - bedrock.fetch.start              { urlPath, method, hasCallerSignal }
 *  - bedrock.fetch.signal_abort       { reason }
 *  - bedrock.fetch.error_pre_response { name, message }
 *  - bedrock.fetch.headers            { status }
 *  - bedrock.fetch.first_byte         { byteLength }
 *  - bedrock.fetch.done               { totalBytes, chunkCount }
 *  - bedrock.fetch.body_error         { name, message, totalBytes, ... }
 *  - bedrock.fetch.body_cancel        { reason, totalBytes, ... }
 */
// Match `(typeof globalThis.fetch)`'s call signature without inheriting its
// extra static methods (e.g. Bun's `preconnect`), which the wrapped function
// can't satisfy. Callers cast the result back to `typeof globalThis.fetch`
// when handing it to the AI SDK — the SDK only invokes it as a function.
type FetchFn = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

/**
 * Optional signal composer. Receives the caller-provided signal (e.g. from
 * streamText) and returns the signal that will actually be passed to fetch
 * (e.g. AbortSignal.any([caller, timeout])). The wrapper observes the result
 * so its `signal_abort` log fires for the composed signal — including the
 * timeout that the caller never sees directly.
 */
type ComposeSignal = (
  caller?: AbortSignal | null,
) => AbortSignal | undefined;

export function wrapFetchWithBedrockLogs(
  baseFetch: FetchFn,
  options: { composeSignal?: ComposeSignal } = {},
): FetchFn {
  return async (input, init) => {
    const callId = newCallId();
    const started = Date.now();

    let urlPath = "(unknown)";
    try {
      const raw =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url;
      urlPath = new URL(raw).pathname;
    } catch {
      // best-effort
    }

    const callerSignal = init?.signal ?? undefined;
    const composedSignal = options.composeSignal
      ? options.composeSignal(callerSignal)
      : callerSignal;

    logEvent("bedrock.fetch.start", {
      callId,
      urlPath,
      method: init?.method ?? "GET",
      hasCallerSignal: !!callerSignal,
      composedSignalAdded: !!composedSignal && composedSignal !== callerSignal,
    });

    if (composedSignal) {
      const onAbort = () => {
        logEvent("bedrock.fetch.signal_abort", {
          callId,
          ageMs: Date.now() - started,
          reason: String(composedSignal.reason ?? "(no reason)").slice(0, 200),
        });
      };
      if (composedSignal.aborted) onAbort();
      else composedSignal.addEventListener("abort", onAbort, { once: true });
    }

    const finalInit: RequestInit | undefined =
      composedSignal !== callerSignal
        ? { ...init, signal: composedSignal }
        : init;

    let response: Response;
    try {
      response = await baseFetch(input, finalInit);
    } catch (err) {
      const e = err as { name?: string; message?: string };
      logEvent("bedrock.fetch.error_pre_response", {
        callId,
        ageMs: Date.now() - started,
        name: e?.name,
        message: typeof e?.message === "string" ? e.message.slice(0, 200) : "",
      });
      throw err;
    }

    logEvent("bedrock.fetch.headers", {
      callId,
      status: response.status,
      ageMs: Date.now() - started,
    });

    if (!response.body) return response;

    const reader = response.body.getReader();
    let firstByteSeen = false;
    let totalBytes = 0;
    let chunkCount = 0;

    const observed = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const { done, value } = await reader.read();
          if (done) {
            logEvent("bedrock.fetch.done", {
              callId,
              ageMs: Date.now() - started,
              totalBytes,
              chunkCount,
            });
            controller.close();
            return;
          }
          chunkCount++;
          totalBytes += value.byteLength;
          if (!firstByteSeen) {
            firstByteSeen = true;
            logEvent("bedrock.fetch.first_byte", {
              callId,
              ageMs: Date.now() - started,
              byteLength: value.byteLength,
            });
          }
          controller.enqueue(value);
        } catch (err) {
          const e = err as { name?: string; message?: string };
          logEvent("bedrock.fetch.body_error", {
            callId,
            ageMs: Date.now() - started,
            chunkCount,
            totalBytes,
            firstByteSeen,
            name: e?.name,
            message:
              typeof e?.message === "string" ? e.message.slice(0, 200) : "",
          });
          controller.error(err);
        }
      },
      cancel(reason) {
        logEvent("bedrock.fetch.body_cancel", {
          callId,
          ageMs: Date.now() - started,
          chunkCount,
          totalBytes,
          reason: String(reason ?? "(no reason)").slice(0, 200),
        });
        reader.cancel(reason).catch(() => {});
      },
    });

    return new Response(observed, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  };
}
