import type {
  LanguageModelV3,
  LanguageModelV3CallOptions,
  LanguageModelV3GenerateResult,
  LanguageModelV3StreamPart,
} from "@ai-sdk/provider";
import { describe, expect, it, vi } from "vitest";
import type {
  InferenceAttempt,
  InferenceRecorder,
  ObservedModelToolCall,
} from "../inference-attempt";
import { runWithInferenceRecorder, UNKNOWN_TOKENS } from "../inference-attempt";
import {
  createNativeRolloutEvidenceCapture,
  withNativeRolloutEvidenceModel,
} from "./capture";
import type { NativeRolloutEvidenceEnvelopeV1 } from "./schema";

const options = {
  prompt: [
    {
      role: "user",
      content: [{ type: "text", text: "hello" }],
    },
  ],
} as LanguageModelV3CallOptions;

const KNOWN_USAGE = {
  inputTokens: { total: 2, noCache: 2, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: 0 },
};

function generated(
  overrides: Partial<LanguageModelV3GenerateResult> = {},
): LanguageModelV3GenerateResult {
  return {
    content: [{ type: "text", text: "world" }],
    finishReason: { unified: "stop", raw: "stop" },
    usage: KNOWN_USAGE,
    warnings: [],
    ...overrides,
  };
}

function streamOf(parts: LanguageModelV3StreamPart[]) {
  return {
    stream: new ReadableStream<LanguageModelV3StreamPart>({
      start(controller) {
        for (const part of parts) controller.enqueue(part);
        controller.close();
      },
    }),
  };
}

function toolCallStream(): ReturnType<typeof streamOf> {
  return streamOf([
    { type: "stream-start", warnings: [] },
    {
      type: "tool-call",
      toolCallId: "tc_1",
      toolName: "read_file",
      input: "{}",
    },
    {
      type: "finish",
      finishReason: { unified: "stop", raw: "stop" },
      usage: KNOWN_USAGE,
    },
  ]);
}

function model(input?: {
  doGenerate?: LanguageModelV3["doGenerate"];
  doStream?: LanguageModelV3["doStream"];
}): LanguageModelV3 {
  return {
    specificationVersion: "v3",
    provider: "openai.chat",
    modelId: "provider-model",
    supportedUrls: {},
    doGenerate: input?.doGenerate ?? (async () => generated()),
    doStream: input?.doStream ?? (async () => toolCallStream()),
  };
}

function wrap(provider: LanguageModelV3): LanguageModelV3 {
  return withNativeRolloutEvidenceModel(provider, {
    requestedModelId: "test-model",
    operationKind: "agent.stream",
  });
}

async function drain(stream: ReadableStream<LanguageModelV3StreamPart>) {
  const reader = stream.getReader();
  const parts: LanguageModelV3StreamPart[] = [];
  for (;;) {
    const next = await reader.read();
    if (next.done) return parts;
    parts.push(next.value);
  }
}

async function drainUntilError(
  stream: ReadableStream<LanguageModelV3StreamPart>,
): Promise<{ parts: LanguageModelV3StreamPart[]; error: unknown }> {
  const reader = stream.getReader();
  const parts: LanguageModelV3StreamPart[] = [];
  for (;;) {
    try {
      const next = await reader.read();
      if (next.done) return { parts, error: undefined };
      parts.push(next.value);
    } catch (error) {
      return { parts, error };
    }
  }
}

interface RecorderEvents {
  dispatched: InferenceAttempt[];
  toolCalls: Array<{ attemptId: string; call: ObservedModelToolCall }>;
  settled: InferenceAttempt[];
}

function makeRecorder(behavior?: {
  beforeDispatch?: (attempt: InferenceAttempt) => Promise<void>;
  beforeToolCall?: (
    attemptId: string,
    call: ObservedModelToolCall,
  ) => Promise<void>;
}): { recorder: InferenceRecorder; events: RecorderEvents } {
  const events: RecorderEvents = {
    dispatched: [],
    toolCalls: [],
    settled: [],
  };
  return {
    events,
    recorder: {
      runId: "run_recording_test",
      beforeDispatch: async (attempt) => {
        events.dispatched.push(attempt);
        await behavior?.beforeDispatch?.(attempt);
      },
      beforeToolCall: async (attemptId, call) => {
        events.toolCalls.push({ attemptId, call });
        await behavior?.beforeToolCall?.(attemptId, call);
      },
      settle: (attempt) => {
        events.settled.push(attempt);
      },
      retry: async () => {},
      flush: async () => {},
    },
  };
}

describe("critical inference recording without evidence capture", () => {
  it("records start, tool calls, and settlement with no capture store installed", async () => {
    const { recorder, events } = makeRecorder();
    const provider = model();
    const providerSpy = vi.spyOn(provider, "doStream");

    const result = await runWithInferenceRecorder(recorder, () =>
      wrap(provider).doStream(options),
    );
    await drain(result.stream);

    expect(providerSpy).toHaveBeenCalledTimes(1);
    expect(events.dispatched).toHaveLength(1);
    expect(events.dispatched[0].lifecycle).toBe("started");
    expect(events.toolCalls).toEqual([
      {
        attemptId: events.dispatched[0].attemptId,
        call: { toolCallId: "tc_1", toolName: "read_file" },
      },
    ]);
    const settled = events.settled.at(-1);
    expect(settled?.lifecycle).toBe("completed");
    expect(settled?.attemptId).toBe(events.dispatched[0].attemptId);
  });

  it("never reads an uncloneable prompt payload when capture is off", async () => {
    const reads: string[] = [];
    const hostileOptions = {
      prompt: [
        {
          role: "user",
          content: [
            {
              type: "text",
              get text() {
                reads.push("prompt");
                return "secret";
              },
            },
          ],
        },
      ],
    } as unknown as LanguageModelV3CallOptions;

    const { recorder, events } = makeRecorder();
    const result = await runWithInferenceRecorder(recorder, () =>
      wrap(model()).doStream(hostileOptions),
    );
    await drain(result.stream);

    expect(reads).toEqual([]);
    expect(events.dispatched).toHaveLength(1);
  });

  it("does not call the provider when the pre-dispatch ack fails", async () => {
    const sentinel = new Error("critical run recorder failed");
    const { recorder } = makeRecorder({
      beforeDispatch: async () => {
        throw sentinel;
      },
    });
    const provider = model();
    const providerSpy = vi.spyOn(provider, "doStream");

    await expect(
      runWithInferenceRecorder(recorder, () =>
        wrap(provider).doStream(options),
      ),
    ).rejects.toBe(sentinel);
    expect(providerSpy).not.toHaveBeenCalled();
  });

  it("blocks a tool call before the consumer sees it", async () => {
    const sentinel = new Error("critical run recorder failed");
    const { recorder, events } = makeRecorder({
      beforeToolCall: async () => {
        throw sentinel;
      },
    });

    const { stream } = await runWithInferenceRecorder(recorder, () =>
      wrap(model()).doStream(options),
    );
    const { parts, error } = await drainUntilError(stream);

    expect(error).toBe(sentinel);
    expect(parts.some((part) => part.type === "tool-call")).toBe(false);
    expect(events.toolCalls).toHaveLength(1);
    expect(events.settled.at(-1)?.lifecycle).toBe("partial");
  });

  it("settles known usage and unknown usage distinctly", async () => {
    const known = makeRecorder();
    const knownStream = await runWithInferenceRecorder(known.recorder, () =>
      wrap(model()).doStream(options),
    );
    await drain(knownStream.stream);
    expect(known.events.settled.at(-1)?.tokens.inclusiveInput).toBe(2);
    expect(known.events.settled.at(-1)?.tokens.output).toBe(1);

    const unknown = makeRecorder();
    const unknownProvider = model({
      doStream: async () =>
        streamOf([
          { type: "stream-start", warnings: [] },
          // A finish part with no provider-reported usage.
          {
            type: "finish",
            finishReason: { unified: "stop", raw: "stop" },
          } as LanguageModelV3StreamPart,
        ]),
    });
    const unknownStream = await runWithInferenceRecorder(unknown.recorder, () =>
      wrap(unknownProvider).doStream(options),
    );
    await drain(unknownStream.stream);
    expect(unknown.events.settled.at(-1)?.tokens).toEqual(UNKNOWN_TOKENS);
  });

  it("keeps terminal settlement synchronous — flush owns the failure", async () => {
    const latched = new Error("critical run recorder failed");
    const settled: InferenceAttempt[] = [];
    const recorder: InferenceRecorder = {
      runId: "run_flush_failure",
      beforeDispatch: async () => {},
      beforeToolCall: async () => {},
      settle: (attempt) => {
        settled.push(attempt);
      },
      retry: async () => {},
      flush: async () => {
        throw latched;
      },
    };

    const { stream } = await runWithInferenceRecorder(recorder, () =>
      wrap(model()).doStream(options),
    );
    await drain(stream);

    expect(settled.at(-1)?.lifecycle).toBe("completed");
    await expect(recorder.flush()).rejects.toBe(latched);
  });

  it("gates generate-result tool calls before the caller sees the result", async () => {
    const provider = model({
      doGenerate: async () =>
        generated({
          content: [
            { type: "text", text: "hi" },
            {
              type: "tool-call",
              toolCallId: "tc_gen",
              toolName: "read_file",
              input: "{}",
            },
          ],
        }),
    });

    const ok = makeRecorder();
    const result = await runWithInferenceRecorder(ok.recorder, () =>
      wrap(provider).doGenerate(options),
    );
    expect(result.content.some((item) => item.type === "tool-call")).toBe(true);
    expect(ok.events.toolCalls).toHaveLength(1);
    expect(ok.events.settled.at(-1)?.lifecycle).toBe("completed");

    const sentinel = new Error("critical run recorder failed");
    const blocked = makeRecorder({
      beforeToolCall: async () => {
        throw sentinel;
      },
    });
    await expect(
      runWithInferenceRecorder(blocked.recorder, () =>
        wrap(provider).doGenerate(options),
      ),
    ).rejects.toBe(sentinel);
    expect(blocked.events.settled).toHaveLength(0);
  });

  it("host capture and the critical recorder see the same attempt identity", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const attempts: InferenceAttempt[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run_host_and_critical",
      sink: {
        write: async (envelope) => {
          envelopes.push(envelope);
        },
      },
      attemptSink: {
        write: async (attempt) => {
          attempts.push(attempt);
        },
      },
    });
    const { recorder, events } = makeRecorder();
    const provider = model();

    const { stream } = await capture.run(() =>
      runWithInferenceRecorder(recorder, () =>
        wrap(provider).doStream(options),
      ),
    );
    await drain(stream);
    await capture.flush();

    expect(envelopes.length).toBeGreaterThan(0);
    const attemptIds = new Set([
      ...events.dispatched.map((attempt) => attempt.attemptId),
      ...events.settled.map((attempt) => attempt.attemptId),
      ...attempts.map((attempt) => attempt.attemptId),
      ...envelopes.map((envelope) => envelope.attempt.attemptId),
    ]);
    expect(attemptIds.size).toBe(1);
  });
});

it("does not dispatch when cancellation arrives during the reservation write", async () => {
  const controller = new AbortController();
  const provider = vi.fn(async () => toolCallStream());
  const { recorder } = makeRecorder({
    beforeDispatch: async () => {
      controller.abort();
    },
  });
  await expect(
    runWithInferenceRecorder(recorder, () =>
      wrap(model({ doStream: provider })).doStream({
        ...options,
        abortSignal: controller.signal,
      }),
    ),
  ).rejects.toMatchObject({ name: "AbortError" });
  expect(provider).not.toHaveBeenCalled();
});
