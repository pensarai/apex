import type {
  LanguageModelV3StreamPart,
  LanguageModelV3StreamResult,
} from "@ai-sdk/provider";
import { simulateReadableStream, stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { createRunInferenceRecorder } from "../runtime/runInference";
import type { RunModelStore } from "../runtime/runModelStore";
import type { ModelRetryDecision } from "./inference-attempt";

const state: { model?: MockLanguageModelV3 } = {};
vi.mock("./utils", async () => ({
  ...(await vi.importActual<typeof import("./utils")>("./utils")),
  getProviderModel: () => state.model,
}));
vi.mock("node:timers/promises", async () => ({
  ...(await vi.importActual<typeof import("node:timers/promises")>(
    "node:timers/promises",
  )),
  setTimeout: async () => undefined,
}));
const { streamResponse } = await import("./ai");

const MODEL = "claude-haiku-4-5";
const usage = {
  inputTokens: { total: 100, noCache: 100, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 10, text: 10, reasoning: undefined },
};

function recordingRetries() {
  const retries: ModelRetryDecision[] = [];
  const store = {
    startModelAttempt: async () => {},
    observeModelToolCall: async () => {},
    settleModelAttempt: async () => {},
    recordRetry: async (
      _r: string,
      _e: string,
      decision: ModelRetryDecision,
    ) => {
      retries.push(decision);
    },
    listModelAttempts: async () => [],
    listRetries: async () => [],
  } as unknown as RunModelStore;
  return {
    retries,
    recorder: createRunInferenceRecorder({
      runId: "run_stream_recovery",
      executionAttemptId: "exec_00000000-0000-4000-8000-000000000002",
      store,
    }),
  };
}

function streamOf(chunks: LanguageModelV3StreamPart[]) {
  return { stream: simulateReadableStream({ chunks }) };
}

function textStream(text: string): LanguageModelV3StreamResult {
  return streamOf([
    { type: "text-start", id: "t0" },
    { type: "text-delta", id: "t0", delta: text },
    { type: "text-end", id: "t0" },
    { type: "finish", finishReason: { unified: "stop", raw: "stop" }, usage },
  ]);
}

function rateLimited(): LanguageModelV3StreamResult {
  return streamOf([
    { type: "stream-start", warnings: [] },
    { type: "error", error: new Error("rate limit exceeded") },
  ]);
}

function probeCall(): LanguageModelV3StreamResult {
  return streamOf([
    { type: "stream-start", warnings: [] },
    {
      type: "tool-call",
      toolCallId: "tc_probe",
      toolName: "probe",
      input: JSON.stringify({ target: "a" }),
    },
    {
      type: "finish",
      finishReason: { unified: "tool-calls", raw: "tool_use" },
      usage,
    },
  ]);
}

async function drain(stream: { fullStream: AsyncIterable<unknown> }) {
  for await (const _part of stream.fullStream) {
    /* consume */
  }
}

const rateLimitCounts = (retries: ModelRetryDecision[]) =>
  retries
    .filter((r) => r.authority === "stream-rate-limit")
    .map((r) => [r.count, r.delayMs]);

beforeEach(() => {
  state.model = undefined;
});

describe("stream recovery is one logical stream", () => {
  it("advances the rate-limit count and backoff across consecutive retries", async () => {
    const { recorder, retries } = recordingRetries();
    const doStream = vi
      .fn()
      .mockImplementationOnce(async () => rateLimited())
      .mockImplementationOnce(async () => rateLimited())
      .mockImplementationOnce(async () => rateLimited())
      .mockImplementationOnce(async () => textStream("Recovered"));
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    await drain(
      streamResponse({
        prompt: "p",
        model: MODEL,
        silent: true,
        inferenceRecorder: recorder,
      }),
    );

    expect(doStream).toHaveBeenCalledTimes(4);
    expect(rateLimitCounts(retries)).toEqual([
      [1, 1000],
      [2, 2000],
      [3, 3000],
    ]);
  });

  it("gives up after MAX_RATE_LIMIT_RETRIES consecutive rate limits", async () => {
    const { recorder, retries } = recordingRetries();
    const doStream = vi.fn(async () => rateLimited());
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    await expect(
      drain(
        streamResponse({
          prompt: "p",
          model: MODEL,
          silent: true,
          inferenceRecorder: recorder,
        }),
      ),
    ).rejects.toThrow("rate limit exceeded");

    expect(doStream).toHaveBeenCalledTimes(21);
    expect(rateLimitCounts(retries).map(([count]) => count)).toEqual(
      Array.from({ length: 20 }, (_, i) => i + 1),
    );
  });

  it("restarts the count once a step completes between failures", async () => {
    const { recorder, retries } = recordingRetries();
    const doStream = vi
      .fn()
      .mockImplementationOnce(async () => rateLimited())
      .mockImplementationOnce(async () => probeCall())
      .mockImplementationOnce(async () => rateLimited())
      .mockImplementationOnce(async () => textStream("Done"));
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    await drain(
      streamResponse({
        prompt: "p",
        model: MODEL,
        silent: true,
        inferenceRecorder: recorder,
        stopWhen: stepCountIs(5),
        tools: {
          probe: {
            inputSchema: z.object({ target: z.string() }),
            execute: async () => "probed",
          },
        },
      }),
    );

    expect(doStream).toHaveBeenCalledTimes(4);
    expect(rateLimitCounts(retries).map(([count]) => count)).toEqual([1, 1]);
  });

  it("resolves result fields from the attempt that recovered", async () => {
    const { recorder } = recordingRetries();
    const doStream = vi
      .fn()
      .mockImplementationOnce(async () => rateLimited())
      .mockImplementationOnce(async () => textStream("Recovered"));
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });

    const result = streamResponse({
      prompt: "p",
      model: MODEL,
      silent: true,
      inferenceRecorder: recorder,
    });
    const responseBeforeConsumption = result.response;
    await drain(result);

    expect(await result.text).toBe("Recovered");
    expect((await result.steps).at(-1)?.text).toBe("Recovered");
    for (const response of [
      await responseBeforeConsumption,
      await result.response,
    ]) {
      expect(response.messages).toEqual([
        {
          role: "assistant",
          content: [
            expect.objectContaining({ type: "text", text: "Recovered" }),
          ],
        },
      ]);
    }
  });

  it("keeps the original attempt's fields when nothing was recovered", async () => {
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      doStream: async () => textStream("First"),
    });

    const result = streamResponse({ prompt: "p", model: MODEL, silent: true });
    await drain(result);

    expect(await result.text).toBe("First");
    expect(await result.finishReason).toBe("stop");
  });

  it("does not wait on a fullStream that was read but never iterated", async () => {
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      doStream: async () => textStream("Unread"),
    });

    const result = streamResponse({ prompt: "p", model: MODEL, silent: true });
    void result.fullStream;

    expect(await result.text).toBe("Unread");
  });
});
