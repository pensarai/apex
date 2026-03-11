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

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
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
