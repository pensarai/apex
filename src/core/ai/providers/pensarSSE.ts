/**
 * Minimal SSE (Server-Sent Events) line parser for consuming the Pensar
 * Bedrock streaming Lambda Function URL.
 *
 * Reads a `ReadableStream<Uint8Array>` and yields `{ event, data }` objects
 * whenever a complete SSE message boundary (blank line) is encountered.
 */

export interface SSEEvent {
  event: string;
  data: string;
}

function isConnectionError(error: unknown): boolean {
  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    const name = error.name.toLowerCase();
    const patterns = [
      "network",
      "connection",
      "abort",
      "socket",
      "econnreset",
      "epipe",
      "etimedout",
      "enetunreach",
    ];
    return patterns.some(
      (pattern) => message.includes(pattern) || name.includes(pattern),
    );
  }
  return false;
}

export async function* parseSSE(
  stream: ReadableStream<Uint8Array>,
): AsyncGenerator<SSEEvent> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let currentEvent = "message";
  let currentData: string[] = [];
  let totalBytes = 0;
  let chunkCount = 0;
  let eventCount = 0;
  let receivedMessageStop = false;

  try {
    while (true) {
      let done: boolean;
      let value: Uint8Array | undefined;

      try {
        const readResult = await reader.read();
        done = readResult.done;
        value = readResult.value;
      } catch (readError) {
        console.error(
          `[parseSSE] read error after ${chunkCount} chunks, ${totalBytes} bytes, ${eventCount} events:`,
          readError,
        );

        if (isConnectionError(readError)) {
          throw new Error(
            `Connection closed unexpectedly during streaming (received ${eventCount} events, ${totalBytes} bytes). ` +
              `This may be a temporary network issue.`,
            { cause: readError },
          );
        }
        throw readError;
      }

      if (done || !value) {
        console.error(
          `[parseSSE] stream done: ${chunkCount} chunks, ${totalBytes} bytes, ${eventCount} events yielded, remaining buffer=${buffer.length} chars`,
        );
        if (buffer.length > 0) {
          console.error(`[parseSSE] remaining buffer: ${buffer.slice(0, 500)}`);
        }
        break;
      }

      chunkCount++;
      totalBytes += value.byteLength;
      const decoded = decoder.decode(value, { stream: true });

      if (chunkCount <= 3) {
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
            const eventToYield = {
              event: currentEvent,
              data: currentData.join("\n"),
            };

            try {
              const parsed = JSON.parse(eventToYield.data);
              if (parsed.type === "message_stop") {
                receivedMessageStop = true;
              }
            } catch {
              // Ignore parse errors, just pass through
            }

            yield eventToYield;
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
      console.error(`[parseSSE] flushing final event: ${currentEvent}`);
      yield { event: currentEvent, data: currentData.join("\n") };
    }

    if (eventCount === 0) {
      console.error(
        `[parseSSE] WARNING: stream ended with 0 events! totalBytes=${totalBytes}, chunks=${chunkCount}`,
      );
    } else if (!receivedMessageStop && eventCount > 0) {
      console.error(
        `[parseSSE] WARNING: stream ended without message_stop event (${eventCount} events received)`,
      );
    }
  } finally {
    reader.releaseLock();
  }
}
