import { describe, it, expect, vi } from "vitest";
import {
  StreamIdleTimeoutError,
  withIdleTimeout,
  createToolExecutionGate,
} from "./ai";

// Minimal chunk shape used by the gate — mirrors what the wrapper sees
// from the AI SDK's `fullStream` (only the fields we actually inspect).
type Chunk = { type: string; toolCallId?: string };

describe("withIdleTimeout", () => {
  it("passes through chunks when stream is healthy", async () => {
    async function* source() {
      yield "a";
      yield "b";
      yield "c";
    }

    const collected: string[] = [];
    for await (const chunk of withIdleTimeout(source(), 1000)) {
      collected.push(chunk);
    }
    expect(collected).toEqual(["a", "b", "c"]);
  });

  it("throws StreamIdleTimeoutError when stream stalls", async () => {
    async function* stallingSource() {
      yield "a";
      // Stall forever after first chunk
      await new Promise(() => {});
    }

    const collected: string[] = [];
    await expect(async () => {
      for await (const chunk of withIdleTimeout(stallingSource(), 50)) {
        collected.push(chunk);
      }
    }).rejects.toThrow(StreamIdleTimeoutError);

    expect(collected).toEqual(["a"]);
  });

  it("throws StreamIdleTimeoutError when stream never yields", async () => {
    // eslint-disable-next-line require-yield -- intentional: tests timeout when source never produces
    async function* neverYields() {
      await new Promise(() => {});
    }

    await expect(async () => {
      for await (const _chunk of withIdleTimeout(neverYields(), 50)) {
        // should not reach here
      }
    }).rejects.toThrow(StreamIdleTimeoutError);
  });

  it("resets the idle timer on each chunk", async () => {
    async function* slowButAlive() {
      for (let i = 0; i < 5; i++) {
        await new Promise((r) => setTimeout(r, 30));
        yield i;
      }
    }

    const collected: number[] = [];
    for await (const chunk of withIdleTimeout(slowButAlive(), 80)) {
      collected.push(chunk);
    }
    expect(collected).toEqual([0, 1, 2, 3, 4]);
  });

  it("skips the timeout while isIdleTimerActive returns false", async () => {
    // The consumer signals "expected long pause" by flipping the flag in
    // its for-await body — same pattern the production wrapper uses with
    // the tool-execution gate. The predicate is read AFTER the previous
    // chunk's body ran, so the second iteration sees `active === false`
    // and waits indefinitely instead of arming the timer.
    async function* withGap() {
      yield "open";
      await new Promise((r) => setTimeout(r, 200));
      yield "close";
    }

    let active = true;
    const collected: string[] = [];
    for await (const chunk of withIdleTimeout(withGap(), 50, () => active)) {
      if (chunk === "open") active = false;
      else if (chunk === "close") active = true;
      collected.push(chunk);
    }
    expect(collected).toEqual(["open", "close"]);
  });

  it("calls iterator.return on timeout to clean up the source", async () => {
    const returnSpy = vi
      .fn()
      .mockResolvedValue({ done: true, value: undefined });

    const fakeIterable: AsyncIterable<string> = {
      [Symbol.asyncIterator]() {
        let first = true;
        return {
          async next() {
            if (first) {
              first = false;
              return { done: false as const, value: "a" };
            }
            return new Promise(() => {});
          },
          return: returnSpy,
        };
      },
    };

    const collected: string[] = [];
    try {
      for await (const chunk of withIdleTimeout(fakeIterable, 50)) {
        collected.push(chunk);
      }
    } catch {
      // expected
    }

    expect(collected).toEqual(["a"]);
    expect(returnSpy).toHaveBeenCalled();
  });
});

describe("StreamIdleTimeoutError", () => {
  it("has the correct name and message", () => {
    const err = new StreamIdleTimeoutError(300_000);
    expect(err.name).toBe("StreamIdleTimeoutError");
    expect(err.message).toBe("Stream idle for 300s — no chunks received");
    expect(err).toBeInstanceOf(Error);
  });
});

describe("createToolExecutionGate", () => {
  it("opens on tool-call and closes on tool-result", () => {
    const gate = createToolExecutionGate();
    expect(gate.shouldEnforceIdleTimeout()).toBe(true);

    gate.observe({ type: "tool-call", toolCallId: "tc_1" });
    expect(gate.shouldEnforceIdleTimeout()).toBe(false);

    gate.observe({ type: "tool-result", toolCallId: "tc_1" });
    expect(gate.shouldEnforceIdleTimeout()).toBe(true);
  });

  it("tracks parallel tool calls independently by id", () => {
    const gate = createToolExecutionGate();
    gate.observe({ type: "tool-call", toolCallId: "tc_1" });
    gate.observe({ type: "tool-call", toolCallId: "tc_2" });
    expect(gate.shouldEnforceIdleTimeout()).toBe(false);

    gate.observe({ type: "tool-result", toolCallId: "tc_1" });
    expect(gate.shouldEnforceIdleTimeout()).toBe(false);

    gate.observe({ type: "tool-result", toolCallId: "tc_2" });
    expect(gate.shouldEnforceIdleTimeout()).toBe(true);
  });

  it("dedupes a duplicate tool-call for the same id", () => {
    const gate = createToolExecutionGate();
    gate.observe({ type: "tool-call", toolCallId: "tc_1" });
    gate.observe({ type: "tool-call", toolCallId: "tc_1" });
    gate.observe({ type: "tool-result", toolCallId: "tc_1" });
    expect(gate.shouldEnforceIdleTimeout()).toBe(true);
  });

  it("ignores a tool-result with no matching open tool-call", () => {
    const gate = createToolExecutionGate();
    gate.observe({ type: "tool-result", toolCallId: "tc_orphan" });
    gate.observe({ type: "tool-result", toolCallId: "tc_orphan" });
    expect(gate.shouldEnforceIdleTimeout()).toBe(true);

    gate.observe({ type: "tool-call", toolCallId: "tc_1" });
    expect(gate.shouldEnforceIdleTimeout()).toBe(false);
  });

  it("ignores non-tool chunks", () => {
    const gate = createToolExecutionGate();
    gate.observe({ type: "text-delta" });
    gate.observe({ type: "tool-input-start", toolCallId: "tc_1" });
    gate.observe({ type: "tool-input-delta", toolCallId: "tc_1" });
    gate.observe({ type: "step-finish" });
    expect(gate.shouldEnforceIdleTimeout()).toBe(true);
  });
});

describe("idle timeout + tool-execution gate (integration)", () => {
  // Regression: the 5-minute idle timeout introduced in #698 was firing during
  // long-running tool calls (e.g. run_attack_surface, which spawns a multi-
  // minute sub-agent). The auto-resume path then re-issued the same tool call
  // and a duplicate sub-agent appeared in the TUI. Wired together, the gate +
  // withIdleTimeout must let an arbitrarily long tool gap pass through.
  it("does not fire on a tool-execution gap longer than the idle timeout", async () => {
    const idleMs = 50;
    const toolDurationMs = 250; // 5x the idle window

    async function* providerStream(): AsyncGenerator<Chunk> {
      yield { type: "text-delta" };
      yield { type: "tool-call", toolCallId: "tc_attack_surface" };
      // Provider stream is silent while the tool runs.
      await new Promise((r) => setTimeout(r, toolDurationMs));
      yield { type: "tool-result", toolCallId: "tc_attack_surface" };
      yield { type: "text-delta" };
    }

    const gate = createToolExecutionGate();
    const seen: string[] = [];

    for await (const chunk of withIdleTimeout(
      providerStream(),
      idleMs,
      gate.shouldEnforceIdleTimeout,
    )) {
      gate.observe(chunk);
      seen.push(chunk.type);
    }

    expect(seen).toEqual([
      "text-delta",
      "tool-call",
      "tool-result",
      "text-delta",
    ]);
  });

  it("still fires when the model stream stalls between text-deltas", async () => {
    // Same wiring, but the stall happens *after* the tool finishes — i.e.
    // the model itself is wedged. The original PR (#698) must still catch
    // this so Bedrock streams that hang mid-response are surfaced.
    async function* providerStream(): AsyncGenerator<Chunk> {
      yield { type: "text-delta" };
      yield { type: "tool-call", toolCallId: "tc_1" };
      await new Promise((r) => setTimeout(r, 100));
      yield { type: "tool-result", toolCallId: "tc_1" };
      // Stall forever — model is wedged.
      await new Promise(() => {});
    }

    const gate = createToolExecutionGate();
    const seen: string[] = [];

    await expect(async () => {
      for await (const chunk of withIdleTimeout(
        providerStream(),
        50,
        gate.shouldEnforceIdleTimeout,
      )) {
        gate.observe(chunk);
        seen.push(chunk.type);
      }
    }).rejects.toThrow(StreamIdleTimeoutError);

    expect(seen).toEqual(["text-delta", "tool-call", "tool-result"]);
  });

  it("tolerates parallel tool calls with overlapping execution windows", async () => {
    async function* providerStream(): AsyncGenerator<Chunk> {
      yield { type: "tool-call", toolCallId: "tc_a" };
      yield { type: "tool-call", toolCallId: "tc_b" };
      await new Promise((r) => setTimeout(r, 200));
      yield { type: "tool-result", toolCallId: "tc_a" };
      // Idle gap > timeout while tc_b is still open — must NOT fire.
      await new Promise((r) => setTimeout(r, 200));
      yield { type: "tool-result", toolCallId: "tc_b" };
    }

    const gate = createToolExecutionGate();
    const seen: string[] = [];

    for await (const chunk of withIdleTimeout(
      providerStream(),
      50,
      gate.shouldEnforceIdleTimeout,
    )) {
      gate.observe(chunk);
      seen.push(chunk.type);
    }

    expect(seen).toEqual([
      "tool-call",
      "tool-call",
      "tool-result",
      "tool-result",
    ]);
  });
});
