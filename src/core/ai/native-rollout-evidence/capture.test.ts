import type {
  LanguageModelV3,
  LanguageModelV3CallOptions,
  LanguageModelV3GenerateResult,
  LanguageModelV3StreamPart,
  LanguageModelV3Usage,
} from "@ai-sdk/provider";
import { describe, expect, it, vi } from "vitest";
import type { InferenceAttempt } from "../inference-attempt";
import {
  createNativeRolloutEvidenceCapture,
  runWithNativeRolloutOperation,
  runWithNativeRolloutSession,
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

function generated(
  overrides: Partial<LanguageModelV3GenerateResult> = {},
): LanguageModelV3GenerateResult {
  return {
    content: [{ type: "text", text: "world" }],
    finishReason: { unified: "stop", raw: "stop" },
    usage: {
      inputTokens: {
        total: 2,
        noCache: 2,
        cacheRead: 0,
        cacheWrite: 0,
      },
      outputTokens: { total: 1, text: 1, reasoning: 0 },
    },
    request: { body: { messages: ["hello"] } },
    response: {
      id: "response-1",
      modelId: "effective-model",
      body: { choices: [{ text: "world" }] },
    },
    warnings: [],
    ...overrides,
  };
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
    doStream:
      input?.doStream ??
      (async () => ({
        stream: new ReadableStream<LanguageModelV3StreamPart>({
          start(controller) {
            controller.enqueue({ type: "stream-start", warnings: [] });
            controller.enqueue({ type: "text-start", id: "text-1" });
            controller.enqueue({
              type: "text-delta",
              id: "text-1",
              delta: "world",
            });
            controller.enqueue({ type: "text-end", id: "text-1" });
            controller.enqueue({
              type: "finish",
              finishReason: { unified: "stop", raw: "stop" },
              usage: generated().usage,
              providerMetadata: {
                openai: {
                  logprobs: [{ token: "world", logprob: -0.25 }],
                },
              },
            });
            controller.close();
          },
        }),
        request: { body: { messages: ["hello"] } },
      })),
  };
}

async function drain(stream: ReadableStream<LanguageModelV3StreamPart>) {
  const values: LanguageModelV3StreamPart[] = [];
  const reader = stream.getReader();
  for (;;) {
    const result = await reader.read();
    if (result.done) break;
    values.push(result.value);
  }
  return values;
}

describe("native rollout capture", () => {
  it("shares one physical-call identity with payload-free attempt events", async () => {
    const evidence: NativeRolloutEvidenceEnvelopeV1[] = [];
    const attempts: InferenceAttempt[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-shared-attempt",
      sink: {
        write: (envelope) => {
          evidence.push(envelope);
        },
      },
      attemptSink: {
        write: (attempt) => {
          attempts.push(attempt);
        },
      },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(model(), {
        requestedModelId: "requested-model",
        operationKind: "agent.stream",
        sessionId: "ses-shared-attempt",
      });
      await wrapped.doGenerate(options);
    });
    await capture.flush();

    expect(attempts).toHaveLength(2);
    expect(attempts.map((attempt) => attempt.lifecycle)).toEqual([
      "started",
      "completed",
    ]);
    expect(attempts[0]?.attemptId).toBe(evidence[0]?.attempt.attemptId);
    expect(attempts[1]).toMatchObject({
      attemptId: evidence[0]?.attempt.attemptId,
      idempotencyKey: evidence[0]?.attempt.idempotencyKey,
      attribution: {
        runId: "run-shared-attempt",
        sessionId: "ses-shared-attempt",
      },
      tokens: {
        inclusiveInput: 2,
        uncachedInput: 2,
        cacheRead: 0,
        cacheWrite: 0,
        output: 1,
      },
    });
  });

  it("records only authoritative child-session attribution", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-nested",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(() =>
      runWithNativeRolloutSession(
        {
          sessionId: "ses-child",
          parentSessionId: "ses-parent",
          parentToolCallId: "call-spawn-child",
        },
        async () => {
          const wrapped = withNativeRolloutEvidenceModel(model(), {
            requestedModelId: "requested-model",
            operationKind: "agent.stream",
            sessionId: "ignored-child-alias",
          });
          await wrapped.doGenerate(options);
        },
      ),
    );
    await capture.flush();

    expect(envelopes).toEqual([
      expect.objectContaining({
        sessionId: "ses-child",
        parent: {
          sessionId: "ses-parent",
          toolCallId: "call-spawn-child",
        },
      }),
    ]);
    expect(() =>
      runWithNativeRolloutSession(
        { sessionId: "ses-child", parentSessionId: "ses-parent" },
        () => undefined,
      ),
    ).toThrow("parentSessionId and parentToolCallId");
  });

  it("isolates inference-attempt observer failure from provider and evidence", async () => {
    const doGenerate = vi.fn(async () => generated());
    const evidence: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-attempt-observer-failure",
      sink: {
        write: (envelope) => {
          evidence.push(envelope);
        },
      },
      attemptSink: {
        write: () => Promise.reject(new Error("observer unavailable")),
      },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(model({ doGenerate }), {
        requestedModelId: "requested-model",
        operationKind: "structured.generate",
      });
      await expect(wrapped.doGenerate(options)).resolves.toMatchObject({
        content: generated().content,
      });
    });
    const report = await capture.flush();

    expect(doGenerate).toHaveBeenCalledOnce();
    expect(evidence).toHaveLength(1);
    expect(report.state).toBe("limited");
    expect(report.diagnostics).toEqual([
      { code: "attempt_sink_failure", message: expect.any(String) },
      { code: "attempt_sink_failure", message: expect.any(String) },
    ]);
  });

  it("bounds an unresponsive inference-attempt observer", async () => {
    vi.useFakeTimers();
    try {
      let writeSignal: AbortSignal | undefined;
      const evidence: NativeRolloutEvidenceEnvelopeV1[] = [];
      const capture = createNativeRolloutEvidenceCapture({
        enabled: true,
        runId: "run-attempt-observer-timeout",
        sink: {
          write: (envelope) => {
            evidence.push(envelope);
          },
        },
        attemptSink: {
          write: (_attempt, context) => {
            writeSignal = context.signal;
            return new Promise(() => {});
          },
        },
        limits: { maxPendingRecords: 2, sinkTimeoutMs: 5 },
      });

      await capture.run(async () => {
        const wrapped = withNativeRolloutEvidenceModel(model(), {
          requestedModelId: "requested-model",
          operationKind: "structured.generate",
        });
        await wrapped.doGenerate(options);
      });
      const pendingReport = capture.flush();
      await vi.advanceTimersByTimeAsync(5);

      await expect(pendingReport).resolves.toMatchObject({
        state: "limited",
        attemptedRecords: 1,
        writtenRecords: 1,
        diagnostics: [
          { code: "attempt_sink_delivery_unknown" },
          { code: "attempt_sink_delivery_unknown" },
        ],
      });
      expect(evidence).toHaveLength(1);
      expect(writeSignal?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps native evidence when attempt usage cannot be normalized", async () => {
    const evidence: NativeRolloutEvidenceEnvelopeV1[] = [];
    const attempts: InferenceAttempt[] = [];
    const invalidUsage = {
      inputTokens: {
        total: -1,
        noCache: -1,
        cacheRead: 0,
        cacheWrite: 0,
      },
      outputTokens: { total: 1, text: 1, reasoning: 0 },
    } as LanguageModelV3Usage;
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-invalid-attempt-usage",
      sink: {
        write: (envelope) => {
          evidence.push(envelope);
        },
      },
      attemptSink: {
        write: (attempt) => {
          attempts.push(attempt);
        },
      },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(
        model({
          doGenerate: async () => generated({ usage: invalidUsage }),
        }),
        {
          requestedModelId: "requested-model",
          operationKind: "structured.generate",
        },
      );
      await wrapped.doGenerate(options);
    });
    const report = await capture.flush();

    expect(evidence).toHaveLength(1);
    expect(attempts.at(-1)).toMatchObject({
      lifecycle: "completed",
      tokens: {
        inclusiveInput: null,
        uncachedInput: null,
        cacheRead: null,
        cacheWrite: null,
        output: null,
      },
    });
    expect(report).toMatchObject({
      state: "limited",
      attemptedRecords: 1,
      writtenRecords: 1,
      diagnostics: [{ code: "attempt_usage_unavailable" }],
    });
  });

  it("is disabled by default and leaves the model unwrapped", async () => {
    const sink = vi.fn();
    const base = model();
    const capture = createNativeRolloutEvidenceCapture({
      runId: "run-disabled",
      sink: { write: sink },
    });

    await capture.run(async () => {
      expect(
        withNativeRolloutEvidenceModel(base, {
          requestedModelId: "requested-model",
          operationKind: "agent.stream",
        }),
      ).toBe(base);
      await base.doGenerate(options);
    });

    expect(await capture.flush()).toMatchObject({
      state: "disabled",
      attemptedRecords: 0,
      writtenRecords: 0,
    });
    expect(sink).not.toHaveBeenCalled();
  });

  it("captures exposed request, response, model, and native metadata", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const base = model({
      doGenerate: async () =>
        generated({
          providerMetadata: {
            openai: {
              responseId: "response-1",
              logprobs: [{ token: "world", logprob: 0 }],
            },
          },
        }),
    });
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-1",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(base, {
        requestedModelId: "requested-model",
        operationKind: "structured.generate",
        sessionId: "ses_1",
      });
      await wrapped.doGenerate(options);
    });
    const report = await capture.flush();

    expect(report).toMatchObject({
      state: "complete",
      attemptedRecords: 1,
      writtenRecords: 1,
      droppedRecords: 0,
    });
    expect(envelopes).toHaveLength(1);
    expect(envelopes[0]).toMatchObject({
      runId: "run-1",
      sessionId: "ses_1",
      operationKind: "structured.generate",
      attempt: { sequence: 1, lifecycle: "completed" },
      requested: { modelId: "requested-model" },
      effective: { modelId: "effective-model" },
      native: { logprobs: { state: "available", value: [0] } },
      boundary: {
        input: { native: { state: "available" } },
        output: {
          normalized: { state: "available" },
          native: { state: "available" },
        },
      },
    });
  });

  it("links physical retries without repeating the provider call", async () => {
    let calls = 0;
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const attempts: InferenceAttempt[] = [];
    const base = model({
      doGenerate: async () => {
        calls += 1;
        if (calls === 1) throw new Error("retryable fixture");
        return generated();
      },
    });
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-retry",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
      attemptSink: {
        write: (attempt) => {
          attempts.push(attempt);
        },
      },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(base, {
        requestedModelId: "requested-model",
        operationKind: "structured.generate",
      });
      await runWithNativeRolloutOperation(
        { operationKind: "structured.generate" },
        async () => {
          await expect(wrapped.doGenerate(options)).rejects.toThrow(
            "retryable fixture",
          );
          await wrapped.doGenerate(options);
        },
      );
    });
    await capture.flush();

    expect(calls).toBe(2);
    expect(envelopes).toHaveLength(2);
    expect(envelopes.map((entry) => entry.attempt.lifecycle)).toEqual([
      "retried",
      "completed",
    ]);
    expect(envelopes[1].turnId).toBe(envelopes[0].turnId);
    expect(envelopes[1].attempt).toMatchObject({
      sequence: 2,
      rootAttemptId: envelopes[0].attempt.attemptId,
      previousAttemptId: envelopes[0].attempt.attemptId,
      idempotencyKey: envelopes[0].attempt.idempotencyKey,
    });
    expect(attempts.map((attempt) => attempt.lifecycle)).toEqual([
      "started",
      "retried",
      "started",
      "completed",
    ]);
    expect(attempts[2]).toMatchObject({
      attemptId: envelopes[1].attempt.attemptId,
      idempotencyKey: envelopes[0].attempt.idempotencyKey,
      lineage: {
        sequence: 2,
        previousAttemptId: envelopes[0].attempt.attemptId,
      },
    });
  });

  it("does not classify a later unscoped call as a retry", async () => {
    let calls = 0;
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-independent-calls",
      sink: {
        write(envelope) {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(
        model({
          doGenerate: async () => {
            calls += 1;
            if (calls === 1) throw new Error("independent failure");
            return generated();
          },
        }),
        {
          requestedModelId: "requested-model",
          operationKind: "structured.generate",
        },
      );
      await expect(wrapped.doGenerate(options)).rejects.toThrow(
        "independent failure",
      );
      await wrapped.doGenerate(options);
    });
    await capture.flush();

    expect(envelopes).toHaveLength(2);
    expect(envelopes.map((entry) => entry.attempt.lifecycle).sort()).toEqual([
      "completed",
      "failed",
    ]);
    expect(
      envelopes.some((entry) => entry.attempt.lifecycle === "retried"),
    ).toBe(false);
    expect(new Set(envelopes.map((entry) => entry.turnId)).size).toBe(2);
  });

  it("records a terminal failed attempt only when the run flushes", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-failed",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });

    await capture
      .run(async () => {
        const wrapped = withNativeRolloutEvidenceModel(
          model({
            doGenerate: async () => Promise.reject(new Error("failed")),
          }),
          {
            requestedModelId: "requested-model",
            operationKind: "structured.generate",
          },
        );
        await wrapped.doGenerate(options);
      })
      .catch(() => {});

    expect(envelopes).toHaveLength(0);
    const report = await capture.flush();
    expect(envelopes[0]?.attempt.lifecycle).toBe("failed");
    expect(report.state).toBe("interrupted");
  });

  it("does not lose concurrent failed attempts with the same operation", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-parallel-failures",
      sink: {
        write(envelope) {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(
        model({ doGenerate: async () => Promise.reject(new Error("failed")) }),
        {
          requestedModelId: "requested-model",
          operationKind: "structured.generate",
        },
      );
      await Promise.allSettled([
        wrapped.doGenerate(options),
        wrapped.doGenerate(options),
      ]);
    });
    await capture.flush();

    expect(envelopes).toHaveLength(2);
    expect(envelopes.map((entry) => entry.attempt.lifecycle)).toEqual([
      "failed",
      "failed",
    ]);
    expect(
      new Set(envelopes.map((entry) => entry.attempt.attemptId)).size,
    ).toBe(2);
  });

  it("tees a complete stream without changing its parts", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-stream",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });
    let observed: LanguageModelV3StreamPart[] = [];

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(model(), {
        requestedModelId: "requested-model",
        operationKind: "agent.stream",
      });
      observed = await drain((await wrapped.doStream(options)).stream);
    });
    await capture.flush();

    expect(observed.map((part) => part.type)).toEqual([
      "stream-start",
      "text-start",
      "text-delta",
      "text-end",
      "finish",
    ]);
    expect(envelopes[0]).toMatchObject({
      attempt: { lifecycle: "completed" },
      native: { logprobs: { state: "available", value: [-0.25] } },
      boundary: {
        output: {
          normalized: { state: "available" },
          native: { state: "unsupported" },
        },
      },
    });
  });

  it("marks a cancelled stream interrupted and never duplicates it on flush", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-abort",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(async () => {
      const base = model({
        doStream: async () => ({
          stream: new ReadableStream<LanguageModelV3StreamPart>({
            pull(controller) {
              controller.enqueue({
                type: "text-delta",
                id: "text-1",
                delta: "partial",
              });
            },
          }),
          request: { body: { messages: ["hello"] } },
        }),
      });
      const wrapped = withNativeRolloutEvidenceModel(base, {
        requestedModelId: "requested-model",
        operationKind: "agent.stream",
      });
      const reader = (await wrapped.doStream(options)).stream.getReader();
      await reader.read();
      await reader.cancel("fixture abort");
    });
    await capture.flush();

    expect(envelopes).toHaveLength(1);
    expect(envelopes[0]).toMatchObject({
      attempt: { lifecycle: "aborted" },
      boundary: { output: { normalized: { state: "interrupted" } } },
    });
  });

  it("keeps a received terminal finish complete when cancelled before done", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-finish-cancel",
      sink: {
        write(envelope) {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(async () => {
      const base = model({
        doStream: async () => ({
          stream: new ReadableStream<LanguageModelV3StreamPart>({
            start(controller) {
              controller.enqueue({
                type: "finish",
                finishReason: { unified: "stop", raw: "stop" },
                usage: generated().usage,
              });
            },
          }),
          request: { body: { messages: ["hello"] } },
        }),
      });
      const wrapped = withNativeRolloutEvidenceModel(base, {
        requestedModelId: "requested-model",
        operationKind: "agent.stream",
      });
      const reader = (await wrapped.doStream(options)).stream.getReader();
      expect((await reader.read()).value?.type).toBe("finish");
      await reader.cancel();
    });
    await capture.flush();

    expect(envelopes).toHaveLength(1);
    expect(envelopes[0]).toMatchObject({
      attempt: { lifecycle: "completed" },
      boundary: { output: { normalized: { state: "available" } } },
    });
  });

  it("returns an unchanged provider stream when collector setup fails", async () => {
    const stream = new ReadableStream<LanguageModelV3StreamPart>();
    const lock = stream.getReader();
    const result = { stream, request: { body: { input: "hello" } } };
    const doStream = vi.fn(async () => result);
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-wrapper-failure",
      sink: { write() {} },
    });

    const observed = await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(model({ doStream }), {
        requestedModelId: "requested-model",
        operationKind: "agent.stream",
      });
      return wrapped.doStream(options);
    });
    const report = await capture.flush();
    lock.releaseLock();

    expect(observed).toBe(result);
    expect(doStream).toHaveBeenCalledOnce();
    expect(report).toMatchObject({
      state: "limited",
      attemptedRecords: 0,
      diagnostics: [{ code: "capture_failure" }],
    });
  });

  it("labels helper operations without changing model inputs", async () => {
    const seen: LanguageModelV3CallOptions[] = [];
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const base = model({
      doGenerate: async (input) => {
        seen.push(input);
        return generated();
      },
    });
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-helper",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(base, {
        requestedModelId: "requested-model",
        operationKind: "agent.stream",
      });
      await runWithNativeRolloutOperation(
        { operationKind: "tool.repair" },
        () => wrapped.doGenerate(options),
      );
    });
    await capture.flush();

    expect(seen).toEqual([options]);
    expect(envelopes[0]?.operationKind).toBe("tool.repair");
  });

  it("isolates concurrent run sinks", async () => {
    const runs = new Map<string, string[]>();
    const execute = async (runId: string) => {
      const capture = createNativeRolloutEvidenceCapture({
        enabled: true,
        runId,
        sink: {
          write: (envelope) => {
            const entries = runs.get(runId) ?? [];
            entries.push(envelope.runId);
            runs.set(runId, entries);
          },
        },
      });
      await capture.run(async () => {
        const wrapped = withNativeRolloutEvidenceModel(model(), {
          requestedModelId: "requested-model",
          operationKind: "structured.generate",
        });
        await Promise.resolve();
        await wrapped.doGenerate(options);
      });
      return capture.flush();
    };

    await Promise.all([execute("run-a"), execute("run-b")]);
    expect(runs).toEqual(
      new Map([
        ["run-a", ["run-a"]],
        ["run-b", ["run-b"]],
      ]),
    );
  });

  it("keeps resumed and compacted call contexts attributed to their session", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-contexts",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(async () => {
      const sessionA = withNativeRolloutEvidenceModel(model(), {
        requestedModelId: "requested-model",
        operationKind: "agent.stream",
        sessionId: "ses_a",
      });
      const sessionB = withNativeRolloutEvidenceModel(model(), {
        requestedModelId: "requested-model",
        operationKind: "agent.stream",
        sessionId: "ses_b",
      });
      await sessionA.doGenerate({
        ...options,
        prompt: [
          {
            role: "user",
            content: [{ type: "text", text: "full history" }],
          },
        ],
      });
      await Promise.all([
        sessionA.doGenerate({
          ...options,
          prompt: [
            {
              role: "user",
              content: [{ type: "text", text: "compacted history" }],
            },
          ],
        }),
        sessionB.doGenerate({
          ...options,
          prompt: [
            {
              role: "user",
              content: [{ type: "text", text: "nested session context" }],
            },
          ],
        }),
      ]);
    });
    await capture.flush();

    const recordedPrompts = envelopes.map((envelope) => {
      const input = envelope.assets.find(
        (asset) => asset.ref === envelope.boundary.input.normalizedRef.ref,
      );
      return { sessionId: envelope.sessionId, content: input?.content };
    });
    expect(recordedPrompts).toEqual([
      expect.objectContaining({
        sessionId: "ses_a",
        content: expect.objectContaining({
          prompt: expect.arrayContaining([
            expect.objectContaining({
              content: expect.arrayContaining([
                expect.objectContaining({ text: "full history" }),
              ]),
            }),
          ]),
        }),
      }),
      expect.objectContaining({
        sessionId: "ses_a",
        content: expect.objectContaining({
          prompt: expect.arrayContaining([
            expect.objectContaining({
              content: expect.arrayContaining([
                expect.objectContaining({ text: "compacted history" }),
              ]),
            }),
          ]),
        }),
      }),
      expect.objectContaining({
        sessionId: "ses_b",
        content: expect.objectContaining({
          prompt: expect.arrayContaining([
            expect.objectContaining({
              content: expect.arrayContaining([
                expect.objectContaining({ text: "nested session context" }),
              ]),
            }),
          ]),
        }),
      }),
    ]);
  });

  it("isolates sink failure from a successful provider response", async () => {
    const doGenerate = vi.fn(async () => generated());
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-sink-failure",
      sink: { write: () => Promise.reject(new Error("offline sink failed")) },
    });

    const result = await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(model({ doGenerate }), {
        requestedModelId: "requested-model",
        operationKind: "structured.generate",
      });
      return wrapped.doGenerate(options);
    });
    const report = await capture.flush();

    expect(result.content).toEqual(generated().content);
    expect(doGenerate).toHaveBeenCalledOnce();
    expect(report).toMatchObject({
      state: "limited",
      attemptedRecords: 1,
      writtenRecords: 0,
      droppedRecords: 1,
      diagnostics: [{ code: "sink_failure" }],
    });
  });

  it("bounds the pending sink queue without delaying provider calls", async () => {
    let release: (() => void) | undefined;
    const firstWrite = new Promise<void>((resolve) => {
      release = resolve;
    });
    const write = vi
      .fn<(envelope: NativeRolloutEvidenceEnvelopeV1) => Promise<void>>()
      .mockReturnValueOnce(firstWrite)
      .mockResolvedValue(undefined);
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-queue-limit",
      sink: { write },
      limits: { maxPendingRecords: 1 },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(model(), {
        requestedModelId: "requested-model",
        operationKind: "structured.generate",
      });
      await wrapped.doGenerate(options);
      await wrapped.doGenerate(options);
    });
    release?.();
    const report = await capture.flush();

    expect(write).toHaveBeenCalledOnce();
    expect(report).toMatchObject({
      state: "limited",
      attemptedRecords: 2,
      writtenRecords: 1,
      droppedRecords: 1,
      diagnostics: [{ code: "queue_limit" }],
    });
  });

  it("bounds an unresponsive sink without failing the provider call", async () => {
    vi.useFakeTimers();
    try {
      let writeSignal: AbortSignal | undefined;
      const capture = createNativeRolloutEvidenceCapture({
        enabled: true,
        runId: "run-sink-timeout",
        sink: {
          write: (_envelope, context) => {
            writeSignal = context.signal;
            return new Promise(() => {});
          },
        },
        limits: { maxPendingRecords: 1, sinkTimeoutMs: 5 },
      });

      await capture.run(async () => {
        const wrapped = withNativeRolloutEvidenceModel(model(), {
          requestedModelId: "requested-model",
          operationKind: "structured.generate",
        });
        await wrapped.doGenerate(options);
      });
      const pendingReport = capture.flush();
      await vi.advanceTimersByTimeAsync(5);

      await expect(pendingReport).resolves.toMatchObject({
        state: "limited",
        writtenRecords: 0,
        droppedRecords: 0,
        deliveryUnknownRecords: 1,
        diagnostics: [{ code: "sink_delivery_unknown" }],
      });
      expect(writeSignal?.aborted).toBe(true);

      await capture.run(async () => {
        const wrapped = withNativeRolloutEvidenceModel(model(), {
          requestedModelId: "requested-model",
          operationKind: "structured.generate",
        });
        await wrapped.doGenerate(options);
      });
      await expect(capture.flush()).resolves.toMatchObject({
        state: "limited",
        attemptedRecords: 2,
        writtenRecords: 0,
        droppedRecords: 1,
        deliveryUnknownRecords: 1,
        diagnostics: [
          { code: "sink_delivery_unknown" },
          { code: "queue_limit" },
        ],
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("finalizes an unconsumed stream as partial when the run flushes", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-unconsumed-stream",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(model(), {
        requestedModelId: "requested-model",
        operationKind: "agent.stream",
      });
      await wrapped.doStream(options);
    });
    await capture.flush();

    expect(envelopes).toHaveLength(1);
    expect(envelopes[0]).toMatchObject({
      attempt: { lifecycle: "partial" },
      boundary: { output: { normalized: { state: "interrupted" } } },
    });
  });

  it("replaces oversized normalized input with a bounded marker", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-asset-limit",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
      limits: { maxAssetBytes: 256 },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(model(), {
        requestedModelId: "requested-model",
        operationKind: "structured.generate",
      });
      await wrapped.doGenerate({
        ...options,
        prompt: [
          {
            role: "user",
            content: [{ type: "text", text: "x".repeat(2_000) }],
          },
        ],
      });
    });
    await capture.flush();

    const envelope = envelopes[0];
    expect(envelope?.limitations).toContainEqual(
      expect.objectContaining({ code: "asset_limit" }),
    );
    expect(envelope?.assets.every((asset) => asset.byteLength <= 256)).toBe(
      true,
    );
  });
});
