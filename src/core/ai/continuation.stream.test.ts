import type { StreamTextResult, ToolSet } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("ai", async () => {
  const actual = await vi.importActual<typeof import("ai")>("ai");
  const testState = { calls: 0, firstFinish: "stop" };
  return {
    ...actual,
    __continuationTestState: testState,
    streamText: vi.fn(() => {
      testState.calls += 1;
      const attempt = testState.calls;
      return {
        fullStream: (async function* () {
          if (attempt === 1) {
            yield { type: "finish-step", finishReason: testState.firstFinish };
            return;
          }
          yield {
            type: "tool-result",
            toolName: "response",
            toolCallId: "response-1",
            output: { success: true, responseAccepted: true },
          };
          yield { type: "finish-step", finishReason: "tool-calls" };
        })(),
        response: Promise.resolve({
          messages:
            attempt === 1
              ? [{ role: "assistant", content: "unfinished turn" }]
              : [],
        }),
      } as unknown as StreamTextResult<ToolSet, never>;
    }),
  };
});

const { streamResponse } = await import("./ai");
const aiModule = (await import("ai")) as unknown as typeof import("ai") & {
  __continuationTestState: { calls: number; firstFinish: string };
};
const { streamText, __continuationTestState: state } = aiModule;

afterEach(() => {
  vi.mocked(streamText).mockClear();
  state.calls = 0;
  state.firstFinish = "stop";
});

describe("streamResponse terminal-contract recovery", () => {
  it("resumes a silent stop that omitted the response tool", async () => {
    const stream = streamResponse({
      model: "claude-sonnet-4-5",
      prompt: "continue",
      tools: { response: {} } as unknown as ToolSet,
      silent: true,
    });

    for await (const _chunk of stream.fullStream) {
      // Drain the composed stream.
    }
    expect(streamText).toHaveBeenCalledTimes(2);
  });

  it("resumes a turn truncated at the provider output limit", async () => {
    state.firstFinish = "length";
    const stream = streamResponse({
      model: "claude-sonnet-4-5",
      prompt: "continue",
      tools: { response: {} } as unknown as ToolSet,
      silent: true,
    });

    for await (const _chunk of stream.fullStream) {
      // Drain the composed stream.
    }
    expect(streamText).toHaveBeenCalledTimes(2);
  });
});
