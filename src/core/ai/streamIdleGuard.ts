// Errors a byte stream after `idleTimeoutMs` of total silence (a half-open
// socket that stalls without FIN/RST), while letting a stream that keeps
// dribbling bytes run as long as it needs. Used to bound the Bedrock response
// stream, which no runtime keepalive can rescue once the peer goes silent.

import { type StreamTelemetry, wallNow } from "./streamTelemetry";

// Marker (not just `instanceof`) so the resume logic in ai.ts can still
// recognize this after the AI SDK rewraps it as an APICallError with `cause`.
export class ProviderStreamIdleError extends Error {
  readonly isProviderStreamIdle = true as const;
  constructor(idleTimeoutMs: number) {
    super(`Provider stream idle for ${idleTimeoutMs}ms`);
    this.name = "ProviderStreamIdleError";
  }
}

export interface IdleGuardOptions {
  /** Silence before aborting, ms. Every byte resets it. Default 90_000. */
  idleTimeoutMs?: number;
  telemetry?: StreamTelemetry;
}

export function idleGuardedStream(
  source: ReadableStream<Uint8Array>,
  options: IdleGuardOptions = {},
): ReadableStream<Uint8Array> {
  const idleTimeoutMs = options.idleTimeoutMs ?? 90_000;
  const reader = source.getReader();

  return new ReadableStream<Uint8Array>({
    // `pull` runs only when the consumer wants more, so backpressure (not a
    // dead socket) never trips the timer.
    async pull(controller) {
      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      const idle = new Promise<never>((_, reject) => {
        timeoutId = setTimeout(
          () => reject(new ProviderStreamIdleError(idleTimeoutMs)),
          idleTimeoutMs,
        );
      });

      try {
        const result = await Promise.race([reader.read(), idle]);
        if (result.done) {
          options.telemetry?.finish(wallNow());
          controller.close();
          return;
        }
        options.telemetry?.recordByte(result.value.byteLength, wallNow());
        controller.enqueue(result.value);
      } catch (err) {
        options.telemetry?.wedge(
          err instanceof Error ? err.message : String(err),
          wallNow(),
        );
        options.telemetry?.finish(wallNow());
        await reader.cancel(err).catch(() => {});
        controller.error(err);
      } finally {
        if (timeoutId) clearTimeout(timeoutId);
      }
    },
    cancel(reason) {
      options.telemetry?.finish(wallNow());
      return reader.cancel(reason);
    },
  });
}

export function idleGuardedResponse(
  response: Response,
  options: IdleGuardOptions = {},
): Response {
  if (!response.body) return response;
  return new Response(idleGuardedStream(response.body, options), {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}
