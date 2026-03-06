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

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });

      const lines = buffer.split("\n");
      // Keep the last (potentially incomplete) line in the buffer
      buffer = lines.pop() ?? "";

      for (let line of lines) {
        // Trim carriage return if present (handles both \r\n and \n line endings)
        line = line.replace(/\r$/, "");

        if (line === "") {
          // Blank line = end of SSE message
          if (currentData.length > 0) {
            yield { event: currentEvent, data: currentData.join("\n") };
          }
          currentEvent = "message";
          currentData = [];
        } else if (line.startsWith("event:")) {
          currentEvent = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          currentData.push(line.slice(5).trim());
        }
        // Ignore id:, retry:, and comment lines (: prefix)
      }
    }

    // Flush remaining data if stream ended without trailing blank line
    if (currentData.length > 0) {
      yield { event: currentEvent, data: currentData.join("\n") };
    }
  } finally {
    reader.releaseLock();
  }
}
