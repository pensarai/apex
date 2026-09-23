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
  it.each([
    "normalized",
    "native",
  ] as const)("retains a bounded %s stream prefix including its JSON envelope", async (boundary) => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const part: LanguageModelV3StreamPart =
      boundary === "native"
        ? { type: "raw", rawValue: "x".repeat(120) }
        : { type: "text-delta", id: "t", delta: "x".repeat(81) };
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-envelope-limit",
      limits: { maxAssetBytes: 256 },
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });
    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(
        model({
          doStream: async () => ({
            stream: new ReadableStream({
              start(controller) {
                controller.enqueue(part);
                controller.enqueue(part);
                controller.enqueue({
                  type: "finish",
                  finishReason: { unified: "stop", raw: "stop" },
                  usage: generated().usage,
                });
                controller.close();
              },
            }),
          }),
        }),
        { requestedModelId: "fixture", operationKind: "agent.stream" },
      );
      expect(
        await drain(
          (await wrapped.doStream({ ...options, includeRawChunks: true }))
            .stream,
        ),
      ).toEqual([
        part,
        part,
        {
          type: "finish",
          finishReason: { unified: "stop", raw: "stop" },
          usage: generated().usage,
        },
      ]);
    });
    await capture.flush();
    const output = envelopes[0]?.boundary.output[boundary];
    expect(output).toMatchObject({
      state: "truncated",
      partial: expect.any(Object),
    });
    const reference =
      output?.state === "truncated" ? output.partial : undefined;
    const asset = envelopes[0]?.assets.find(
      (item) => item.ref === reference?.ref,
    );
    expect(asset?.content).toEqual(
      boundary === "native" ? { chunks: ["x".repeat(120)] } : { parts: [part] },
    );
  });

  it.each([
    "doGenerate",
    "doStream",
  ] as const)("classifies cancellation before %s returns as aborted", async (method) => {
    for (const signaled of [true, false]) {
      const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
      const controller = new AbortController();
      const error = signaled
        ? new Error("cancelled")
        : new DOMException("cancelled", "AbortError");
      if (signaled) controller.abort(error);
      const capture = createNativeRolloutEvidenceCapture({
        enabled: true,
        runId: "run-aborted",
        sink: {
          write: (envelope) => {
            envelopes.push(envelope);
          },
        },
      });
      await capture.run(() =>
        runWithNativeRolloutOperation(
          { operationKind: "agent.stream" },
          async () => {
            const wrapped = withNativeRolloutEvidenceModel(
              model({
                [method]: async () => {
                  throw error;
                },
              }),
              {
                requestedModelId: "fixture",
                operationKind: "agent.stream",
              },
            );
            await expect(
              wrapped[method]({ ...options, abortSignal: controller.signal }),
            ).rejects.toBe(error);
          },
        ),
      );
      await capture.flush();
      expect(envelopes).toHaveLength(1);
      expect(envelopes[0]).toMatchObject({
        attempt: { lifecycle: "aborted" },
        boundary: { output: { normalized: { state: "interrupted" } } },
      });
    }
  });

  it.each([
    "error-part",
    "read-error",
  ])("retains retry lineage after a returned stream %s", async (failure) => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-stream-failure",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });
    let calls = 0;
    await capture.run(() =>
      runWithNativeRolloutOperation(
        { operationKind: "agent.stream" },
        async () => {
          const wrapped = withNativeRolloutEvidenceModel(
            model({
              doStream: async () => {
                if (++calls > 1) return await model().doStream(options);
                let read = false;
                return {
                  stream: new ReadableStream({
                    pull(controller) {
                      if (!read) {
                        read = true;
                        controller.enqueue({
                          type: "text-delta",
                          id: "t",
                          delta: "prefix",
                        });
                      } else if (failure === "error-part") {
                        controller.enqueue({
                          type: "error",
                          error: new Error("retry"),
                        });
                        controller.close();
                      } else controller.error(new Error("retry"));
                    },
                  }),
                };
              },
            }),
            { requestedModelId: "fixture", operationKind: "agent.stream" },
          );
          const first = drain((await wrapped.doStream(options)).stream);
          if (failure === "read-error")
            await expect(first).rejects.toThrow("retry");
          else await first;
          await drain((await wrapped.doStream(options)).stream);
        },
      ),
    );
    await capture.flush();
    expect(envelopes.map((entry) => entry.attempt.lifecycle)).toEqual([
      "retried",
      "completed",
    ]);
    expect(envelopes[1]?.turnId).toBe(envelopes[0]?.turnId);
    expect(envelopes[1]?.attempt).toMatchObject({
      sequence: 2,
      previousAttemptId: envelopes[0]?.attempt.attemptId,
      idempotencyKey: envelopes[0]?.attempt.idempotencyKey,
    });
    const output = envelopes[0]?.boundary.output.normalized;
    expect(output).toMatchObject({
      state: "interrupted",
      partial: expect.any(Object),
    });
    const reference =
      output?.state === "interrupted" ? output.partial : undefined;
    expect(
      envelopes[0]?.assets.find((asset) => asset.ref === reference?.ref)
        ?.content,
    ).toMatchObject({
      parts: expect.arrayContaining([
        { type: "text-delta", id: "t", delta: "prefix" },
      ]),
    });
  });

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

  it("records an independent terminal failure without waiting for run flush", async () => {
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

    expect(envelopes).toHaveLength(1);
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

  it("persists more independent failures than the pending-write limit with a healthy sink", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-many-independent-failures",
      sink: {
        write(envelope) {
          envelopes.push(envelope);
        },
      },
      limits: { maxPendingRecords: 32 },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(
        model({ doGenerate: async () => Promise.reject(new Error("failed")) }),
        {
          requestedModelId: "requested-model",
          operationKind: "structured.generate",
        },
      );
      for (let index = 0; index < 64; index++) {
        await expect(wrapped.doGenerate(options)).rejects.toThrow("failed");
      }
    });
    const report = await capture.flush();

    expect(envelopes).toHaveLength(64);
    expect(
      new Set(envelopes.map((entry) => entry.attempt.attemptId)).size,
    ).toBe(64);
    expect(
      envelopes.every((entry) => entry.attempt.lifecycle === "failed"),
    ).toBe(true);
    expect(report).toMatchObject({
      attemptedRecords: 64,
      writtenRecords: 64,
      droppedRecords: 0,
      deliveryUnknownRecords: 0,
    });
    expect(report.diagnostics).not.toContainEqual(
      expect.objectContaining({ code: "queue_limit" }),
    );
  });

  it("retires failed async operation scopes before run flush", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-closed-failure-scopes",
      sink: {
        write(envelope) {
          envelopes.push(envelope);
        },
      },
      limits: { maxPendingRecords: 4 },
    });

    await capture.run(async () => {
      for (let index = 0; index < 12; index++) {
        await runWithNativeRolloutOperation(
          { operationKind: "structured.generate" },
          async () => {
            const wrapped = withNativeRolloutEvidenceModel(
              model({
                doGenerate: async () => Promise.reject(new Error("failed")),
              }),
              {
                requestedModelId: "requested-model",
                operationKind: "structured.generate",
              },
            );
            await expect(wrapped.doGenerate(options)).rejects.toThrow("failed");
          },
        );
      }
    });

    expect(envelopes).toHaveLength(12);
    const report = await capture.flush();
    expect(report).toMatchObject({
      attemptedRecords: 12,
      writtenRecords: 12,
      droppedRecords: 0,
      deliveryUnknownRecords: 0,
    });
  });

  it("reports when bounded retry retention finalizes an older failure", async () => {
    let calls = 0;
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-retry-retention-limit",
      sink: {
        write(envelope) {
          envelopes.push(envelope);
        },
      },
      limits: { maxPendingRecords: 1 },
    });

    await capture.run(() =>
      runWithNativeRolloutOperation(
        { operationKind: "structured.generate" },
        async () => {
          const wrapped = withNativeRolloutEvidenceModel(
            model({
              doGenerate: async () => {
                calls += 1;
                if (calls <= 2) throw new Error("retryable fixture");
                await new Promise<void>((resolve) => queueMicrotask(resolve));
                return generated();
              },
            }),
            {
              requestedModelId: "requested-model",
              operationKind: "structured.generate",
            },
          );
          await Promise.allSettled([
            wrapped.doGenerate(options),
            wrapped.doGenerate(options),
          ]);
          await wrapped.doGenerate(options);
        },
      ),
    );
    const report = await capture.flush();

    expect(envelopes.map((entry) => entry.attempt.lifecycle)).toEqual([
      "failed",
      "retried",
      "completed",
    ]);
    expect(report).toMatchObject({
      state: "limited",
      attemptedRecords: 3,
      writtenRecords: 3,
      droppedRecords: 0,
      diagnostics: [
        {
          code: "retry_lineage_limit",
          message: expect.stringContaining("retry"),
        },
      ],
    });
  });

  it("bounds independent failure delivery when the sink never settles", async () => {
    vi.useFakeTimers();
    try {
      const signals: AbortSignal[] = [];
      const capture = createNativeRolloutEvidenceCapture({
        enabled: true,
        runId: "run-failure-sink-timeout",
        sink: {
          write: (_envelope, context) => {
            signals.push(context.signal);
            return new Promise(() => {});
          },
        },
        limits: { maxPendingRecords: 2, sinkTimeoutMs: 5 },
      });

      await capture.run(async () => {
        const wrapped = withNativeRolloutEvidenceModel(
          model({
            doGenerate: async () => Promise.reject(new Error("failed")),
          }),
          {
            requestedModelId: "requested-model",
            operationKind: "structured.generate",
          },
        );
        for (let index = 0; index < 8; index++) {
          await expect(wrapped.doGenerate(options)).rejects.toThrow("failed");
        }
      });
      const pendingReport = capture.flush();
      await vi.advanceTimersByTimeAsync(5);
      const report = await pendingReport;

      expect(signals).toHaveLength(2);
      expect(signals.every((signal) => signal.aborted)).toBe(true);
      expect(report).toMatchObject({
        state: "limited",
        attemptedRecords: 8,
        writtenRecords: 0,
        droppedRecords: 6,
        deliveryUnknownRecords: 2,
      });
      expect(
        report.diagnostics.filter(({ code }) => code === "queue_limit"),
      ).toHaveLength(6);
      expect(
        report.diagnostics.filter(
          ({ code }) => code === "sink_delivery_unknown",
        ),
      ).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
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

  it("marks a complete raw stream prefix truncated without changing provider parts", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const parts: LanguageModelV3StreamPart[] = [
      { type: "raw", rawValue: { text: "x".repeat(100) } },
      { type: "raw", rawValue: { text: "x".repeat(2_000) } },
      {
        type: "finish",
        finishReason: { unified: "stop", raw: "stop" },
        usage: generated().usage,
      },
    ];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-raw-limit",
      sink: {
        write(envelope) {
          envelopes.push(envelope);
        },
      },
      limits: { maxAssetBytes: 1_024 },
    });
    let observed: LanguageModelV3StreamPart[] = [];

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(
        model({
          doStream: async () => ({
            stream: new ReadableStream<LanguageModelV3StreamPart>({
              start(controller) {
                for (const part of parts) controller.enqueue(part);
                controller.close();
              },
            }),
          }),
        }),
        {
          requestedModelId: "requested-model",
          operationKind: "agent.stream",
        },
      );
      observed = await drain(
        (
          await wrapped.doStream({
            ...options,
            includeRawChunks: true,
          })
        ).stream,
      );
    });
    await capture.flush();

    expect(observed).toEqual(parts);
    expect(envelopes[0]).toMatchObject({
      attempt: { lifecycle: "completed" },
      boundary: {
        output: {
          native: { state: "truncated", partial: expect.any(Object) },
        },
      },
      limitations: [
        expect.objectContaining({
          code: "stream_limit",
          field: "boundary.output.normalized",
        }),
        expect.objectContaining({
          code: "stream_limit",
          field: "boundary.output.native",
        }),
      ],
    });
    const native = envelopes[0]?.boundary.output.native;
    const nativeRef =
      native?.state === "truncated" ? native.partial : undefined;
    expect(
      envelopes[0]?.assets.find((asset) => asset.ref === nativeRef?.ref)
        ?.content,
    ).toEqual({ chunks: [{ text: "x".repeat(100) }] });
  });

  it("marks a raw stream prefix interrupted when the provider ends without finish", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const rawPart = { type: "raw", rawValue: { text: "partial" } } as const;
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-raw-interrupted",
      sink: {
        write(envelope) {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(
        model({
          doStream: async () => ({
            stream: new ReadableStream<LanguageModelV3StreamPart>({
              start(controller) {
                controller.enqueue(rawPart);
                controller.close();
              },
            }),
          }),
        }),
        {
          requestedModelId: "requested-model",
          operationKind: "agent.stream",
        },
      );
      expect(
        await drain(
          (
            await wrapped.doStream({
              ...options,
              includeRawChunks: true,
            })
          ).stream,
        ),
      ).toEqual([rawPart]);
    });
    await capture.flush();

    expect(envelopes[0]).toMatchObject({
      attempt: { lifecycle: "partial" },
      boundary: {
        output: {
          normalized: { state: "interrupted" },
          native: { state: "interrupted", partial: expect.any(Object) },
        },
      },
    });
  });

  it("marks a cancelled raw stream prefix interrupted", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-raw-abort",
      sink: {
        write(envelope) {
          envelopes.push(envelope);
        },
      },
    });

    await capture.run(async () => {
      const wrapped = withNativeRolloutEvidenceModel(
        model({
          doStream: async () => ({
            stream: new ReadableStream<LanguageModelV3StreamPart>({
              pull(controller) {
                controller.enqueue({
                  type: "raw",
                  rawValue: { text: "partial" },
                });
              },
            }),
          }),
        }),
        {
          requestedModelId: "requested-model",
          operationKind: "agent.stream",
        },
      );
      const reader = (
        await wrapped.doStream({ ...options, includeRawChunks: true })
      ).stream.getReader();
      expect((await reader.read()).value?.type).toBe("raw");
      await reader.cancel("fixture abort");
    });
    await capture.flush();

    expect(envelopes).toHaveLength(1);
    expect(envelopes[0]).toMatchObject({
      attempt: { lifecycle: "aborted" },
      boundary: {
        output: {
          normalized: { state: "interrupted" },
          native: { state: "interrupted", partial: expect.any(Object) },
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

  it("bounds unconsumed stream finalizers across fresh wrappers", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-many-unconsumed-streams",
      sink: {
        write(envelope) {
          envelopes.push(envelope);
        },
      },
      limits: { maxPendingRecords: 4 },
    });

    await capture.run(async () => {
      for (let index = 0; index < 12; index++) {
        const wrapped = withNativeRolloutEvidenceModel(model(), {
          requestedModelId: "requested-model",
          operationKind: "agent.stream",
        });
        await wrapped.doStream(options);
      }
    });

    expect(envelopes).toHaveLength(8);
    const report = await capture.flush();
    expect(envelopes).toHaveLength(12);
    expect(
      envelopes.every((entry) => entry.attempt.lifecycle === "partial"),
    ).toBe(true);
    expect(report).toMatchObject({
      attemptedRecords: 12,
      writtenRecords: 12,
      droppedRecords: 0,
    });
  });

  it("keeps forwarding an evicted stream without collecting or emitting it again", async () => {
    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const lateParts: LanguageModelV3StreamPart[] = [
      { type: "raw", rawValue: { text: "late raw" } },
      { type: "text-start", id: "late" },
      { type: "text-delta", id: "late", delta: "late text" },
      { type: "text-end", id: "late" },
      {
        type: "finish",
        finishReason: { unified: "stop", raw: "stop" },
        usage: generated().usage,
      },
    ];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-evicted-stream-consumption",
      sink: {
        write(envelope) {
          envelopes.push(envelope);
        },
      },
      limits: { maxPendingRecords: 1 },
    });
    let firstStream: ReadableStream<LanguageModelV3StreamPart> | undefined;

    await capture.run(async () => {
      const first = withNativeRolloutEvidenceModel(
        model({
          doStream: async () => ({
            stream: new ReadableStream<LanguageModelV3StreamPart>({
              start(controller) {
                for (const part of lateParts) controller.enqueue(part);
                controller.close();
              },
            }),
          }),
        }),
        {
          requestedModelId: "requested-model",
          operationKind: "agent.stream",
        },
      );
      firstStream = (await first.doStream(options)).stream;

      const second = withNativeRolloutEvidenceModel(model(), {
        requestedModelId: "requested-model",
        operationKind: "agent.stream",
      });
      await second.doStream(options);
    });

    expect(envelopes).toHaveLength(1);
    if (!firstStream) throw new Error("first stream was not captured");
    expect(await drain(firstStream)).toEqual(lateParts);
    expect(envelopes).toHaveLength(1);
    const report = await capture.flush();
    expect(envelopes).toHaveLength(2);
    expect(envelopes[0]).toMatchObject({
      attempt: { lifecycle: "partial" },
      boundary: {
        output: {
          normalized: { state: "interrupted" },
          native: { state: "interrupted", partial: expect.any(Object) },
        },
      },
    });
    expect(report).toMatchObject({ attemptedRecords: 2, writtenRecords: 2 });
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
