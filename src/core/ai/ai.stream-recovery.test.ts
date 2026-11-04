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

describe("idle recovery exhaustion with owned provider streams", () => {
  it("drains every stalled attempt and stops after three resumes", async () => {
    const nativeTimeout = globalThis.setTimeout;
    const timer = vi
      .spyOn(globalThis, "setTimeout")
      .mockImplementation(((
        callback: (...args: unknown[]) => void,
        delay?: number,
        ...args: unknown[]
      ) =>
        nativeTimeout(
          callback,
          delay === 300_000 ? 100 : delay,
          ...args,
        )) as typeof setTimeout);
    const { recorder, retries } = recordingRetries();
    const lifecycle: string[] = [];
    const signals: AbortSignal[] = [];
    const controllers: ReadableStreamDefaultController<LanguageModelV3StreamPart>[] =
      [];
    const cancelled = new Set<number>();
    const barriers = Array.from({ length: 4 }, () => ({
      started: Promise.withResolvers<void>(),
      release: Promise.withResolvers<void>(),
    }));
    let settled = false;
    let attempts = 0;
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      doStream: async ({ abortSignal }) => {
        const attempt = ++attempts;
        if (attempt > 8) throw new Error("diagnostic runaway guard");
        lifecycle.push(`start:${attempt}`);
        if (!abortSignal) throw new Error("missing attempt abort signal");
        signals.push(abortSignal);
        return {
          stream: new ReadableStream<LanguageModelV3StreamPart>({
            start(controller) {
              controllers.push(controller);
              controller.enqueue({ type: "stream-start", warnings: [] });
              controller.enqueue({ type: "text-start", id: `t${attempt}` });
              controller.enqueue({
                type: "text-delta",
                id: `t${attempt}`,
                delta: "partial",
              });
            },
            async cancel() {
              cancelled.add(attempt);
              lifecycle.push(`cancel:${attempt}`);
              barriers[attempt - 1].started.resolve();
              await barriers[attempt - 1].release.promise;
              lifecycle.push(`drained:${attempt}`);
            },
          }),
        };
      },
    });
    const result = drain(
      streamResponse({
        prompt: "synthetic idle probe",
        model: MODEL,
        silent: true,
        inferenceRecorder: recorder,
      }),
    ).then(
      () => {
        settled = true;
        return undefined;
      },
      (error: unknown) => {
        settled = true;
        return error;
      },
    );
    try {
      for (let i = 0; i < barriers.length; i++) {
        await barriers[i].started.promise;
        await new Promise((resolve) => nativeTimeout(resolve, 150));
        expect(attempts).toBe(i + 1);
        expect(settled).toBe(false);
        expect(lifecycle.at(-1)).toBe(`cancel:${i + 1}`);
        barriers[i].release.resolve();
      }
      expect(await result).toMatchObject({ name: "StreamIdleTimeoutError" });
      expect(attempts).toBe(4);
      expect(
        retries
          .filter((r) => r.authority === "stream-idle")
          .map((r) => r.count),
      ).toEqual([1, 2, 3]);
      expect(lifecycle).toEqual(
        [1, 2, 3, 4].flatMap((i) => [
          `start:${i}`,
          `cancel:${i}`,
          `drained:${i}`,
        ]),
      );
      expect(signals.every((signal) => signal.aborted)).toBe(true);
    } finally {
      barriers.forEach((barrier) => {
        barrier.release.resolve();
      });
      controllers.forEach((controller, index) => {
        if (!cancelled.has(index + 1)) controller.close();
      });
      timer.mockRestore();
    }
  });

  it("returns recovered fields after a stalled attempt has drained", async () => {
    const nativeTimeout = globalThis.setTimeout;
    const timer = vi
      .spyOn(globalThis, "setTimeout")
      .mockImplementation(((
        callback: (...args: unknown[]) => void,
        delay?: number,
        ...args: unknown[]
      ) =>
        nativeTimeout(
          callback,
          delay === 300_000 ? 100 : delay,
          ...args,
        )) as typeof setTimeout);
    let drained = false;
    const doStream = vi
      .fn()
      .mockImplementationOnce(async () => ({
        stream: new ReadableStream<LanguageModelV3StreamPart>({
          start(controller) {
            controller.enqueue({ type: "stream-start", warnings: [] });
          },
          async cancel() {
            await new Promise((resolve) => nativeTimeout(resolve, 2));
            drained = true;
          },
        }),
      }))
      .mockImplementationOnce(async () => {
        expect(drained).toBe(true);
        return textStream("Recovered after idle");
      });
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });
    try {
      const result = streamResponse({
        prompt: "synthetic idle probe",
        model: MODEL,
        silent: true,
      });
      const response = result.response;
      await drain(result);
      expect(await result.text).toBe("Recovered after idle");
      expect((await result.steps).at(-1)?.text).toBe("Recovered after idle");
      expect((await response).messages).toEqual([
        {
          role: "assistant",
          content: [
            expect.objectContaining({
              type: "text",
              text: "Recovered after idle",
            }),
          ],
        },
      ]);
      expect(doStream).toHaveBeenCalledTimes(2);
    } finally {
      timer.mockRestore();
    }
  });
});

describe("incomplete model stream recovery", () => {
  function incomplete() {
    return streamOf([
      {
        type: "error",
        error: Object.assign(new Error("Incomplete model stream"), {
          name: "IncompleteModelStreamError",
        }),
      },
    ]);
  }

  it("continues a serialized protocol failure with the same model and a distinct bounded retry reason", async () => {
    const { recorder, retries } = recordingRetries();
    const doStream = vi
      .fn()
      .mockResolvedValueOnce(incomplete())
      .mockImplementation(async () => textStream("Complete"));
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });
    const result = streamResponse({
      prompt: "synthetic input",
      model: MODEL,
      silent: true,
      inferenceRecorder: recorder,
    });
    await drain(result);
    expect(await result.text).toBe("Complete");
    expect(doStream).toHaveBeenCalledTimes(2);
    expect(retries).toEqual([
      expect.objectContaining({
        authority: "stream-incomplete",
        count: 1,
        maxRetries: 3,
      }),
    ]);
  });

  it("stops after three incomplete-stream continuations", async () => {
    const { recorder, retries } = recordingRetries();
    const doStream = vi.fn(async () => incomplete());
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });
    const result = streamResponse({
      prompt: "synthetic input",
      model: MODEL,
      silent: true,
      inferenceRecorder: recorder,
    });
    await expect(drain(result)).rejects.toMatchObject({
      name: "IncompleteModelStreamError",
    });
    expect(doStream).toHaveBeenCalledTimes(4);
    expect(retries.map(({ count }) => count)).toEqual([1, 2, 3]);
  });

  it("does not repeat a tool already dispatched in an incomplete standalone turn", async () => {
    const effect = vi.fn(async () => "done");
    const doStream = vi.fn(async () =>
      streamOf([
        {
          type: "tool-call",
          toolCallId: "effect",
          toolName: "effect",
          input: "{}",
        },
        {
          type: "error",
          error: Object.assign(new Error("Incomplete model stream"), {
            name: "IncompleteModelStreamError",
          }),
        },
      ]),
    );
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });
    const result = streamResponse({
      prompt: "synthetic input",
      model: MODEL,
      silent: true,
      tools: { effect: { inputSchema: z.object({}), execute: effect } },
    });
    await expect(drain(result)).rejects.toMatchObject({
      name: "IncompleteModelStreamError",
    });
    expect(doStream).toHaveBeenCalledTimes(1);
    expect(effect).toHaveBeenCalledTimes(1);
  });
});

it.each([
  "abort",
  "provider-400",
] as const)("does not recover %s as an incomplete stream", async (scenario) => {
  const abort = new AbortController();
  const doStream = vi.fn(async () => {
    if (scenario === "abort") abort.abort(new Error("cancelled"));
    return streamOf([
      {
        type: "error",
        error:
          scenario === "abort"
            ? Object.assign(new Error("Incomplete stream"), {
                name: "IncompleteModelStreamError",
              })
            : Object.assign(new Error("provider validation failed"), {
                statusCode: 400,
                isRetryable: false,
              }),
      },
    ]);
  });
  state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });
  const result = streamResponse({
    prompt: "synthetic input",
    model: MODEL,
    silent: true,
    abortSignal: abort.signal,
  });
  if (scenario === "abort") {
    await drain(result);
    expect(abort.signal.aborted).toBe(true);
  } else
    await expect(drain(result)).rejects.toThrow("provider validation failed");
  expect(doStream).toHaveBeenCalledTimes(1);
});

describe("source cancellation ownership", () => {
  it.each([
    "Error",
    "AbortError",
    "StreamIdleTimeoutError",
    "IncompleteModelStreamError",
  ])("does not resume after source cancellation rejects %s", async (name) => {
    const nativeTimeout = globalThis.setTimeout;
    const timer = vi
      .spyOn(globalThis, "setTimeout")
      .mockImplementation(((
        callback: (...args: unknown[]) => void,
        delay?: number,
        ...args: unknown[]
      ) =>
        nativeTimeout(
          callback,
          delay === 300_000 ? 20 : delay,
          ...args,
        )) as typeof setTimeout);
    const failure = Object.assign(new Error("source cancellation failed"), {
      name,
    });
    const cancel = vi.fn(async () => {
      throw failure;
    });
    const doStream = vi.fn(async () => ({
      stream: new ReadableStream<LanguageModelV3StreamPart>({
        start(controller) {
          controller.enqueue({ type: "stream-start", warnings: [] });
        },
        cancel,
      }),
    }));
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });
    try {
      await expect(
        drain(
          streamResponse({
            prompt: "synthetic cancellation",
            model: MODEL,
            silent: true,
          }),
        ),
      ).rejects.toMatchObject({
        name: "ModelStreamDrainError",
        cause: failure,
      });
      expect(cancel).toHaveBeenCalledTimes(1);
      expect(doStream).toHaveBeenCalledTimes(1);
    } finally {
      timer.mockRestore();
    }
  });

  it("resumes after acquisition has rejected on abort without an acquired source", async () => {
    const nativeTimeout = globalThis.setTimeout;
    const timer = vi
      .spyOn(globalThis, "setTimeout")
      .mockImplementation(((
        callback: (...args: unknown[]) => void,
        delay?: number,
        ...args: unknown[]
      ) =>
        nativeTimeout(
          callback,
          delay === 300_000 ? 20 : delay,
          ...args,
        )) as typeof setTimeout);
    const failure = Object.assign(new Error("acquisition aborted"), {
      name: "AbortError",
    });
    const doStream = vi
      .fn()
      .mockImplementationOnce(
        ({ abortSignal }: { abortSignal: AbortSignal }) =>
          new Promise((_, reject) =>
            abortSignal.addEventListener("abort", () => reject(failure), {
              once: true,
            }),
          ),
      )
      .mockImplementationOnce(async () =>
        textStream("Acquired after recovery"),
      );
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });
    try {
      const result = streamResponse({
        prompt: "synthetic acquisition",
        model: MODEL,
        silent: true,
      });
      await drain(result);
      expect(await result.text).toBe("Acquired after recovery");
      expect(doStream).toHaveBeenCalledTimes(2);
    } finally {
      timer.mockRestore();
    }
  });

  it("recovers an already-errored source without mistaking its stored error for cancellation failure", async () => {
    const failure = Object.assign(new Error("recorded incomplete stream"), {
      name: "IncompleteModelStreamError",
    });
    const cancel = vi.fn();
    const doStream = vi
      .fn()
      .mockImplementationOnce(async () => ({
        stream: new ReadableStream<LanguageModelV3StreamPart>({
          start(controller) {
            controller.error(failure);
          },
          cancel,
        }),
      }))
      .mockImplementationOnce(async () =>
        textStream("Recovered recorded stream"),
      );
    state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });
    const result = streamResponse({
      prompt: "synthetic recorded stream",
      model: MODEL,
      silent: true,
    });
    await drain(result);
    expect(await result.text).toBe("Recovered recorded stream");
    expect(cancel).not.toHaveBeenCalled();
    expect(doStream).toHaveBeenCalledTimes(2);
  });
});

it.each([
  "close",
  "error",
] as const)("joins source cancellation before an abort listener can %s its readable", async (onAbort) => {
  const nativeTimeout = globalThis.setTimeout;
  const timer = vi
    .spyOn(globalThis, "setTimeout")
    .mockImplementation(((
      callback: (...args: unknown[]) => void,
      delay?: number,
      ...args: unknown[]
    ) =>
      nativeTimeout(
        callback,
        delay === 300_000 ? 20 : delay,
        ...args,
      )) as typeof setTimeout);
  const entered = Promise.withResolvers<void>();
  const cleanup = Promise.withResolvers<void>();
  let cancelStarted = false;
  let signal: AbortSignal | undefined;
  const doStream = vi
    .fn()
    .mockImplementationOnce(
      async ({ abortSignal }: { abortSignal: AbortSignal }) => {
        signal = abortSignal;
        return {
          stream: new ReadableStream<LanguageModelV3StreamPart>({
            start(controller) {
              controller.enqueue({ type: "stream-start", warnings: [] });
              abortSignal.addEventListener(
                "abort",
                () => {
                  if (!cancelStarted) {
                    if (onAbort === "close") controller.close();
                    else
                      controller.error(
                        new DOMException("source aborted", "AbortError"),
                      );
                  }
                  entered.resolve();
                },
                { once: true },
              );
            },
            async cancel() {
              cancelStarted = true;
              await cleanup.promise;
            },
          }),
        };
      },
    )
    .mockImplementationOnce(async () =>
      textStream("Recovered after producer cleanup"),
    );
  state.model = new MockLanguageModelV3({ modelId: MODEL, doStream });
  let settled = false;
  const run = drain(
    streamResponse({
      prompt: "synthetic abort ordering",
      model: MODEL,
      silent: true,
    }),
  ).finally(() => {
    settled = true;
  });
  try {
    await entered.promise;
    await new Promise((resolve) => nativeTimeout(resolve, 30));
    expect(signal?.aborted).toBe(true);
    expect(cancelStarted).toBe(true);
    expect(doStream).toHaveBeenCalledTimes(1);
    expect(settled).toBe(false);
    cleanup.resolve();
    await run;
    expect(doStream).toHaveBeenCalledTimes(2);
  } finally {
    cleanup.resolve();
    await run.catch(() => {});
    timer.mockRestore();
  }
});
