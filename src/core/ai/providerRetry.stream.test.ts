import type { StreamTextResult, ToolSet } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("ai", async () => {
  const actual = await vi.importActual<typeof import("ai")>("ai");
  const testState = { calls: 0 };
  return {
    ...actual,
    __providerRetryTestState: testState,
    streamText: vi.fn(() => {
      testState.calls += 1;
      const attempt = testState.calls;
      return {
        fullStream: (async function* () {
          if (attempt === 1) {
            throw {
              code: 429,
              message: "Provider returned error",
              metadata: { error_type: "rate_limit_exceeded" },
            };
          }
          yield { type: "text-delta", id: "text-1", text: "recovered" };
        })(),
        response: Promise.resolve({ messages: [] }),
      } as unknown as StreamTextResult<ToolSet, never>;
    }),
  };
});

const { streamResponse } = await import("./ai");
const aiModule = (await import("ai")) as unknown as typeof import("ai") & {
  __providerRetryTestState: { calls: number };
};
const { streamText, __providerRetryTestState: state } = aiModule;

afterEach(() => {
  vi.useRealTimers();
  vi.mocked(streamText).mockClear();
  state.calls = 0;
});

describe("streamResponse provider recovery", () => {
  it("resumes after the numeric OpenRouter 429 observed in production", async () => {
    vi.useFakeTimers();
    const stream = streamResponse({
      model: "claude-sonnet-4-5",
      prompt: "continue",
      silent: true,
    });
    const chunks: Array<{ type: string; text?: string }> = [];
    const consume = (async () => {
      for await (const chunk of stream.fullStream) chunks.push(chunk);
    })();

    await vi.advanceTimersByTimeAsync(1_000);
    await consume;

    expect(streamText).toHaveBeenCalledTimes(2);
    expect(chunks).toContainEqual({
      type: "text-delta",
      id: "text-1",
      text: "recovered",
    });
  });
});
