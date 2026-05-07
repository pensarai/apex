// Pins invariant I4 ("error containment") on the outer-catch path of
// `streamResponse`. When `streamText` throws synchronously with a
// context-length error, the catch block falls back to
// `createSummarizationStream`. Before this wrapping, an overflow inside
// that summarization stream — or a non-`ContextLengthExhaustedError`
// thrown by the resumed `streamResponse` — escaped uncaught and leaked
// the raw `AI_APICallError prompt is too long` to the consumer.
//
// This test exists to fail loudly if a future refactor un-wraps that
// path again.

import type { ModelMessage, StreamTextResult, ToolSet } from "ai";
import { describe, expect, it, vi } from "vitest";

vi.mock("ai", async () => {
  const actual = await vi.importActual<typeof import("ai")>("ai");
  return {
    ...actual,
    streamText: vi.fn(() => {
      // Sync-throw a context-length error from streamText. In the AI SDK
      // this is rare but possible (e.g. provider validation rejects the
      // payload before any I/O). The outer try/catch in `streamResponse`
      // exists for exactly this case.
      throw new Error("prompt is too long: 999999 tokens > 200000 maximum");
    }),
  };
});

vi.mock("./utils", async () => {
  const actual = await vi.importActual<typeof import("./utils")>("./utils");
  return {
    ...actual,
    createSummarizationStream: vi.fn(
      () =>
        ({
          // biome-ignore lint/correctness/useYield: throw-only generator simulates streamText error
          fullStream: (async function* () {
            throw new Error(
              "prompt is too long: 999999 tokens > 200000 maximum",
            );
          })(),
          response: Promise.resolve({ messages: [] }),
        }) as unknown as StreamTextResult<ToolSet, never>,
    ),
  };
});

const { streamResponse, ContextLengthExhaustedError } = await import("./ai");

describe("outer-catch summarization is wrapped (I4)", () => {
  it("sync streamText ctx error → recovery cascade → typed terminal error", async () => {
    // A small message set that fits the proactive budget so we DON'T take
    // the proactive escalation branch — we want the outer try/catch to fire.
    const messages: ModelMessage[] = [
      { role: "user" as const, content: "small payload" },
    ];

    const stream = streamResponse({
      model: "claude-sonnet-4-5",
      prompt: "anything",
      messages,
      silent: true,
      // = MAX_RESTART_DEPTH; the very next recursive recovery step will
      // bump past the bound and synthesize the typed terminal error.
      _restartDepth: 3,
    });

    let observed: unknown;
    try {
      for await (const chunk of stream.fullStream) {
        void chunk;
      }
    } catch (err) {
      observed = err;
    }

    // The decisive assertion: the typed terminal error escapes, NOT a raw
    // "prompt is too long" SDK error. If the outer catch were re-unwrapped,
    // this would surface the underlying ctx error instead.
    expect(observed).toBeInstanceOf(ContextLengthExhaustedError);
  });
});
