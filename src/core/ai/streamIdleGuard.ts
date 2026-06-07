/**
 * Connection-liveness guard for a raw byte stream. Errors after `idleTimeoutMs`
 * of byte-silence (a half-open socket that stops sending without FIN/RST) while
 * waiting indefinitely as long as bytes flow. Provider-agnostic — watches raw
 * chunks only, so it works on the Bedrock EventStream body. This is the fix for
 * the document_endpoint hang; no runtime keepalive detects a silent peer.
 */

import { type StreamTelemetry, wallNow } from "./streamTelemetry";

/**
 * Thrown when the transport goes byte-silent. Carries a stable marker so the
 * stream-resume logic in ai.ts recognizes it even after the AI SDK wraps it in
 * an APICallError (provider layers preserve `cause`, not `instanceof`).
 */
export class ProviderStreamIdleError extends Error {
  readonly isProviderStreamIdle = true as const;
  constructor(idleTimeoutMs: number) {
    super(
      `Provider stream idle for ${idleTimeoutMs}ms — transport appears dead/half-open`,
    );
    this.name = "ProviderStreamIdleError";
  }
}

export interface IdleGuardOptions {
  /** Abort if no bytes arrive for this many ms. Every byte resets it. Default 90_000. */
  idleTimeoutMs?: number;
  telemetry?: StreamTelemetry;
}

/** Idle timer is armed only during an active pull, so backpressure never trips it. */
export function idleGuardedStream(
  source: ReadableStream<Uint8Array>,
  options: IdleGuardOptions = {},
): ReadableStream<Uint8Array> {
  const idleTimeoutMs = options.idleTimeoutMs ?? 90_000;
  const reader = source.getReader();

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      const idlePromise = new Promise<never>((_, reject) => {
        timeoutId = setTimeout(() => {
          reject(new ProviderStreamIdleError(idleTimeoutMs));
        }, idleTimeoutMs);
      });

      try {
        const result = await Promise.race([reader.read(), idlePromise]);
        if (result.done) {
          options.telemetry?.finish(wallNow());
          controller.close();
          return;
        }
        options.telemetry?.recordByte(result.value.byteLength, wallNow());
        controller.enqueue(result.value);
      } catch (err) {
        // Idle fired or read rejected: snapshot, release the socket, propagate.
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

/** Wrap a Response so its body is idle-guarded, preserving status/headers. */
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
