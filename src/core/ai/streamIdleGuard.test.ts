import { describe, expect, it } from "vitest";

import { idleGuardedStream, ProviderStreamIdleError } from "./streamIdleGuard";

const enc = new TextEncoder();

/** Drain a byte stream to a single concatenated string. */
async function drain(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader();
  const dec = new TextDecoder();
  let out = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    out += dec.decode(value, { stream: true });
  }
  return out;
}

/** A stream that enqueues each chunk after its delay (ms from start). */
function timedStream(
  chunks: Array<{ at: number; text: string }>,
): ReadableStream<Uint8Array> {
  const timers: ReturnType<typeof setTimeout>[] = [];
  return new ReadableStream<Uint8Array>({
    start(controller) {
      const maxAt = Math.max(0, ...chunks.map((c) => c.at));
      for (const c of chunks) {
        timers.push(
          setTimeout(() => controller.enqueue(enc.encode(c.text)), c.at),
        );
      }
      timers.push(setTimeout(() => controller.close(), maxAt + 5));
    },
    cancel() {
      for (const t of timers) clearTimeout(t);
    },
  });
}

/** A stream that emits one chunk then goes silent forever (never closes). */
function wedgingStream(firstChunk: string): {
  stream: ReadableStream<Uint8Array>;
  cancelled: () => boolean;
} {
  let wasCancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(enc.encode(firstChunk));
      // ...then never enqueue again and never close — a half-open socket.
    },
    cancel() {
      wasCancelled = true;
    },
  });
  return { stream, cancelled: () => wasCancelled };
}

describe("idleGuardedStream", () => {
  it("passes bytes through unchanged when the source flows steadily", async () => {
    const source = timedStream([
      { at: 0, text: "hello " },
      { at: 20, text: "wedge-" },
      { at: 40, text: "free world" },
    ]);
    const guarded = idleGuardedStream(source, { idleTimeoutMs: 200 });
    expect(await drain(guarded)).toBe("hello wedge-free world");
  });

  it("stays alive across gaps shorter than the idle window", async () => {
    // 60ms gaps under a 150ms window must NOT trip the guard.
    const source = timedStream([
      { at: 0, text: "a" },
      { at: 60, text: "b" },
      { at: 120, text: "c" },
    ]);
    const guarded = idleGuardedStream(source, { idleTimeoutMs: 150 });
    expect(await drain(guarded)).toBe("abc");
  });

  it("errors after the idle window when the source goes byte-silent mid-stream", async () => {
    const { stream, cancelled } = wedgingStream("partial response");
    const guarded = idleGuardedStream(stream, { idleTimeoutMs: 60 });

    const reader = guarded.getReader();
    // First chunk arrives fine.
    const first = await reader.read();
    expect(new TextDecoder().decode(first.value)).toBe("partial response");

    // The next read blocks on a dead socket and must reject within the window.
    await expect(reader.read()).rejects.toThrow(ProviderStreamIdleError);
    // The guard must cancel the upstream so the socket is released.
    expect(cancelled()).toBe(true);
  });

  it("throws a marked ProviderStreamIdleError findable through a cause chain", async () => {
    const { stream } = wedgingStream("x");
    const guarded = idleGuardedStream(stream, { idleTimeoutMs: 40 });
    const reader = guarded.getReader();
    await reader.read();
    let caught: unknown;
    await reader.read().catch((e) => {
      caught = e;
    });
    // The stable marker ai.ts walks for, even when wrapped (e.g. APICallError).
    expect(caught).toBeInstanceOf(ProviderStreamIdleError);
    expect((caught as ProviderStreamIdleError).isProviderStreamIdle).toBe(true);
    // Survives one level of provider wrapping via `cause`.
    const wrapped = new Error("API call failed", { cause: caught });
    expect(
      (wrapped.cause as { isProviderStreamIdle?: boolean }).isProviderStreamIdle,
    ).toBe(true);
  });

  it("records bytes and a wedge on the telemetry hook", async () => {
    const events: string[] = [];
    const fakeTelemetry = {
      recordByte: () => events.push("byte"),
      wedge: () => events.push("wedge"),
      finish: () => events.push("finish"),
    };
    const { stream } = wedgingStream("x");
    const guarded = idleGuardedStream(stream, {
      idleTimeoutMs: 40,
      // Only the three methods the guard calls are exercised here.
      telemetry: fakeTelemetry as never,
    });

    const reader = guarded.getReader();
    await reader.read();
    await reader.read().catch(() => {});

    expect(events).toContain("byte");
    expect(events).toContain("wedge");
    expect(events).toContain("finish");
  });
});
