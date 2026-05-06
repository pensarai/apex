import { describe, expect, it } from "vitest";
import { parseSSE } from "./pensarSSE";

describe("parseSSE", () => {
  it("yields events from a well-formed stream", async () => {
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(
          encoder.encode('event: message\ndata: {"type":"a"}\n\n'),
        );
        controller.enqueue(
          encoder.encode('event: message\ndata: {"type":"b"}\n\n'),
        );
        controller.close();
      },
    });

    const events = [];
    for await (const evt of parseSSE(stream)) {
      events.push(evt);
    }

    expect(events).toEqual([
      { event: "message", data: '{"type":"a"}' },
      { event: "message", data: '{"type":"b"}' },
    ]);
  });

  it("aborts with a descriptive error if the reader stalls past idleTimeoutMs", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start() {
        // Never enqueues or closes — simulates a stalled upstream.
      },
    });

    const start = Date.now();
    let caught: unknown;
    try {
      for await (const _ of parseSSE(stream, { idleTimeoutMs: 100 })) {
        // unreachable
      }
    } catch (err) {
      caught = err;
    }
    const elapsed = Date.now() - start;

    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toMatch(/idle for 100ms/);
    expect(elapsed).toBeGreaterThanOrEqual(90);
    expect(elapsed).toBeLessThan(2_000);
  });

  it("resets the idle timer on each chunk", async () => {
    const encoder = new TextEncoder();
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        controller = c;
      },
    });

    const consume = (async () => {
      const events = [];
      for await (const evt of parseSSE(stream, { idleTimeoutMs: 150 })) {
        events.push(evt);
      }
      return events;
    })();

    // Emit a chunk every 75ms — below the 150ms idle threshold, so no timeout should fire.
    for (let i = 0; i < 4; i++) {
      await new Promise((r) => setTimeout(r, 75));
      controller.enqueue(
        encoder.encode(`event: message\ndata: {"i":${i}}\n\n`),
      );
    }
    controller.close();

    const events = await consume;
    expect(events).toHaveLength(4);
  });
});
