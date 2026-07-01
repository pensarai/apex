/**
 * Minimal SSE (Server-Sent Events) line parser for consuming the Pensar
 * Bedrock streaming Lambda Function URL.
 *
 * Reads a `ReadableStream<Uint8Array>` and yields `{ event, data }` objects
 * whenever a complete SSE message boundary (blank line) is encountered.
 */

import { createLogger } from "../../logger/structured";
import { scopedLogger } from "../../util/lazyLogger";
import { type StreamTelemetry, wallNow } from "../streamTelemetry";

const log = scopedLogger(() => createLogger("pensarSSE"));

export interface SSEEvent {
  event: string;
  data: string;
}

export interface ParseSSEOptions {
  /**
   * Abort if no bytes arrive from the underlying reader for this many ms.
   * Prevents indefinite hangs when the upstream gateway stalls mid-stream.
   * Default: 90_000.
   */
  idleTimeoutMs?: number;
  /** Optional per-stream connection telemetry (see streamTelemetry.ts). */
  telemetry?: StreamTelemetry;
}

export async function* parseSSE(
  stream: ReadableStream<Uint8Array>,
  options: ParseSSEOptions = {},
): AsyncGenerator<SSEEvent> {
  const idleTimeoutMs = options.idleTimeoutMs ?? 90_000;
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let currentEvent = "message";
  let currentData: string[] = [];
  let totalBytes = 0;
  let chunkCount = 0;
  let eventCount = 0;

  try {
    while (true) {
      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      const idlePromise = new Promise<never>((_, reject) => {
        timeoutId = setTimeout(() => {
          reject(
            new Error(
              `SSE stream idle for ${idleTimeoutMs}ms (${chunkCount} chunks, ${eventCount} events received so far)`,
            ),
          );
        }, idleTimeoutMs);
      });

      let result: Awaited<ReturnType<typeof reader.read>>;
      try {
        result = await Promise.race([reader.read(), idlePromise]);
      } catch (err) {
        options.telemetry?.wedge(`no bytes for ${idleTimeoutMs}ms`, wallNow());
        await reader.cancel(err).catch(() => {});
        throw err;
      } finally {
        if (timeoutId) clearTimeout(timeoutId);
      }
      if (result.done) {
        log.debug(
          `stream done: ${chunkCount} chunks, ${totalBytes} bytes, ${eventCount} events yielded, remaining buffer=${buffer.length} chars`,
        );
        if (buffer.length > 0) {
          log.debug(`remaining buffer: ${buffer.slice(0, 500)}`);
        }
        break;
      }

      const value = result.value;
      chunkCount++;
      totalBytes += value.byteLength;
      options.telemetry?.recordByte(value.byteLength, wallNow());
      const decoded = decoder.decode(value, { stream: true });

      if (chunkCount <= 3) {
        log.debug(
          `chunk #${chunkCount}: ${value.byteLength} bytes, preview: ${decoded.slice(0, 200)}`,
        );
      }

      buffer += decoded;

      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";

      for (let line of lines) {
        line = line.replace(/\r$/, "");

        if (line === "") {
          if (currentData.length > 0) {
            eventCount++;
            options.telemetry?.recordEvent(wallNow());
            yield { event: currentEvent, data: currentData.join("\n") };
          }
          currentEvent = "message";
          currentData = [];
        } else if (line.startsWith("event:")) {
          currentEvent = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          currentData.push(line.slice(5).trim());
        }
      }
    }

    if (currentData.length > 0) {
      eventCount++;
      log.debug(`flushing final event: ${currentEvent}`);
      yield { event: currentEvent, data: currentData.join("\n") };
    }

    if (eventCount === 0) {
      log.warn(
        `stream ended with 0 events! totalBytes=${totalBytes}, chunks=${chunkCount}`,
      );
    }
  } finally {
    reader.releaseLock();
  }
}
