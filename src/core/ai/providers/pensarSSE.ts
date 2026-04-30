/**
 * Minimal SSE (Server-Sent Events) line parser for consuming the Pensar
 * Bedrock streaming Lambda Function URL.
 *
 * Reads a `ReadableStream<Uint8Array>` and yields `{ event, data }` objects
 * whenever a complete SSE message boundary (blank line) is encountered.
 */

const DEBUG =
  process.env.PENSAR_DEBUG === "1" || process.env.PENSAR_DEBUG === "true";

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
        await reader.cancel(err).catch(() => {});
        throw err;
      } finally {
        if (timeoutId) clearTimeout(timeoutId);
      }
      if (result.done) {
        if (DEBUG) {
          console.error(
            `[parseSSE] stream done: ${chunkCount} chunks, ${totalBytes} bytes, ${eventCount} events yielded, remaining buffer=${buffer.length} chars`,
          );
          if (buffer.length > 0) {
            console.error(
              `[parseSSE] remaining buffer: ${buffer.slice(0, 500)}`,
            );
          }
        }
        break;
      }

      const value = result.value;
      chunkCount++;
      totalBytes += value.byteLength;
      const decoded = decoder.decode(value, { stream: true });

      if (DEBUG && chunkCount <= 3) {
        console.error(
          `[parseSSE] chunk #${chunkCount}: ${value.byteLength} bytes, preview: ${decoded.slice(0, 200)}`,
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
      if (DEBUG)
        console.error(`[parseSSE] flushing final event: ${currentEvent}`);
      yield { event: currentEvent, data: currentData.join("\n") };
    }

    if (eventCount === 0) {
      console.error(
        `[parseSSE] WARNING: stream ended with 0 events! totalBytes=${totalBytes}, chunks=${chunkCount}`,
      );
    }
  } finally {
    reader.releaseLock();
  }
}
