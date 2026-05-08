// Pins invariant I4 ("error containment") on the proactive-summarization
// escalation path. Before wrapping the proactive return with
// `wrapStreamWithErrorHandler`, an overflow inside the summarization stream
// itself escaped uncaught — the same `AI_APICallError prompt is too long`
// shape that motivated this work in the first place. This test exists to
// fail loudly if a future refactor un-wraps that path.
import { vi, describe, it, expect } from "vitest";
import type { ModelMessage, StreamTextResult, ToolSet } from "ai";

vi.mock("./utils", async () => {
  const actual = await vi.importActual<typeof import("./utils")>("./utils");
  return {
    ...actual,
    // Both the proactive escalation and the reactive Layer 3 fall through
    // to this stream — both should be caught + recovered by the wrapper.
    createSummarizationStream: vi.fn(
      () =>
        ({
          // eslint-disable-next-line require-yield
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

// Imported AFTER vi.mock so the streamResponse closure picks up the stub.
const { streamResponse, ContextLengthExhaustedError } = await import("./ai");

describe("proactive summarization is wrapped (I4)", () => {
  it("recovery exhausts to ContextLengthExhaustedError, not a raw provider error", async () => {
    // Force `proactiveFitFailed=true`: many large user-text messages, no
    // sessionPath. Layer 1 needs sessionPath to run; Layer 2 only touches
    // tool results — neither reduces user text, so fitsBudget stays false.
    const messages: ModelMessage[] = Array.from({ length: 100 }, () => ({
      role: "user" as const,
      content: "x".repeat(50_000),
    }));

    const stream = streamResponse({
      model: "claude-sonnet-4-5",
      prompt: "anything",
      messages,
      silent: true,
      // = MAX_RESTART_DEPTH; any recursive recovery cycle will trip the
      // depth guard at the top of `streamResponse`.
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
    // "prompt is too long" SDK error. If the proactive path were unwrapped
    // again, this would surface the underlying ctx error instead.
    expect(observed).toBeInstanceOf(ContextLengthExhaustedError);
  });
});
