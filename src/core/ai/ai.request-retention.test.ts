// Regression gate for SDK request-body retention: `streamResponse` must keep
// wire requests, tool execution, callbacks, usage, and native rollout capture
// while the SDK retains no serialized request bodies in step history. Later
// steps re-send the whole conversation, so retained bodies would otherwise
// accumulate with every step.

import type { ModelMessage } from "ai";
import { stepCountIs, tool } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { CustomProviders } from "../config/customProviders";
import { runWithStepContext, streamResponse } from "./ai";
import type { NativeRolloutEvidenceEnvelopeV1 } from "./native-rollout-evidence";
import { createNativeRolloutEvidenceCapture } from "./native-rollout-evidence";
import { consumeStream } from "./utils";

const customProviders: CustomProviders = {
  retention: {
    baseUrl: "https://retention.invalid/api",
    apiKeyEnv: "APEX_TEST_RETENTION_KEY",
    models: [
      { id: "fixture", contextLength: 200_000, maxOutputTokens: 32_000 },
    ],
  },
};
const MODEL = "custom:retention:fixture";
const PAYLOAD = "x".repeat(8192);
const TOOL_STEPS = 4;
const TOTAL_STEPS = TOOL_STEPS + 1;

function chunk(delta: Record<string, unknown>, finishReason: string | null) {
  return JSON.stringify({
    id: "fixture",
    object: "chat.completion.chunk",
    created: 0,
    model: "fixture",
    choices: [{ index: 0, delta, finish_reason: finishReason }],
    ...(finishReason
      ? {
          usage: {
            prompt_tokens: 100,
            completion_tokens: 10,
            total_tokens: 110,
          },
        }
      : {}),
  });
}

function sseResponse(index: number): Response {
  const toolStep = index < TOOL_STEPS;
  const delta = toolStep
    ? {
        tool_calls: [
          {
            index: 0,
            id: `call-${index}`,
            type: "function",
            function: {
              name: "fixture",
              arguments: JSON.stringify({ i: index }),
            },
          },
        ],
      }
    : { content: "done" };
  const finishReason = toolStep ? "tool_calls" : "stop";
  return new Response(
    `data: ${chunk(delta, null)}\n\ndata: ${chunk({}, finishReason)}\n\ndata: [DONE]\n\n`,
    { headers: { "content-type": "text/event-stream" } },
  );
}

function nativeInput(envelope: NativeRolloutEvidenceEnvelopeV1): unknown {
  const field = envelope.boundary.input.native;
  if (field.state !== "available") {
    throw new Error(`native input state was ${field.state}`);
  }
  const asset = envelope.assets.find((a) => a.ref === field.value.ref);
  if (!asset) {
    throw new Error("native input asset is missing");
  }
  return asset.content;
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("streamResponse SDK request-body retention", () => {
  it("retains no step-history request bodies while keeping wire requests, callbacks, usage, and native capture", async () => {
    vi.stubEnv("APEX_TEST_RETENTION_KEY", "fixture-key");
    const events: string[] = [];
    const wireBodies: string[] = [];
    let calls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: unknown, init?: RequestInit) => {
        const index = calls++;
        wireBodies.push(String(init?.body));
        events.push(`fetch:${index}`);
        return sseResponse(index);
      }),
    );

    const envelopes: NativeRolloutEvidenceEnvelopeV1[] = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-request-retention",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });

    let toolRuns = 0;
    const usageCalls: Array<{
      model: string;
      input: number;
      output: number;
      context: unknown;
    }> = [];
    const stepRequests: unknown[] = [];
    let finishEvent:
      | {
          totalUsage: {
            inputTokens?: number;
            outputTokens?: number;
            totalTokens?: number;
          };
          text: string;
          steps: Array<{ request: { body?: unknown } }>;
          responseMessages: unknown;
        }
      | undefined;
    const result = await capture.run(() =>
      runWithStepContext({ sessionId: "ses_request_retention" }, async () => {
        const run = streamResponse({
          model: MODEL,
          authConfig: { customProviders },
          prompt: "fixture",
          tools: {
            fixture: tool({
              inputSchema: z.object({ i: z.number() }),
              execute: async ({ i }) => {
                toolRuns++;
                return { i, data: PAYLOAD };
              },
            }),
          },
          stopWhen: stepCountIs(TOTAL_STEPS),
          silent: true,
          usageRecorder: (model, inputTokens, outputTokens, context) => {
            usageCalls.push({
              model,
              input: inputTokens,
              output: outputTokens,
              context,
            });
          },
          onStepFinish: (step) => {
            stepRequests.push(step.request.body);
            events.push(`step:${step.stepNumber}`);
          },
          onFinish: (event) => {
            events.push("finish");
            finishEvent = {
              totalUsage: event.totalUsage,
              text: event.text,
              steps: event.steps,
              responseMessages: event.response.messages,
            };
          },
        });
        let text = "";
        await consumeStream(run, {
          onTextDelta: (delta) => {
            text += delta.text;
          },
        });
        return {
          text,
          steps: await run.steps,
        };
      }),
    );
    await capture.flush();
    const finish = finishEvent;
    if (!finish) throw new Error("onFinish never fired");

    // Wire requests still carry the full growing conversation.
    expect(wireBodies).toHaveLength(TOTAL_STEPS);
    for (let i = 1; i < wireBodies.length; i++) {
      expect(wireBodies[i].length).toBeGreaterThan(wireBodies[i - 1].length);
    }
    expect(wireBodies[TOTAL_STEPS - 1]).toContain(PAYLOAD);
    for (const body of wireBodies) {
      expect(JSON.parse(body)).toMatchObject({
        model: "fixture",
        stream: true,
      });
    }

    // Tool execution, finish reasons, output, and usage are unchanged.
    expect(toolRuns).toBe(TOOL_STEPS);
    expect(result.text).toBe("done");
    expect(result.steps).toHaveLength(TOTAL_STEPS);
    for (let i = 0; i < TOOL_STEPS; i++) {
      expect(result.steps[i].finishReason).toBe("tool-calls");
      expect(result.steps[i].toolCalls).toHaveLength(1);
      expect(result.steps[i].toolCalls[0].toolName).toBe("fixture");
      expect(result.steps[i].toolCalls[0].input).toEqual({ i });
      expect(result.steps[i].toolResults[0].output).toEqual({
        i,
        data: PAYLOAD,
      });
    }
    expect(result.steps[TOOL_STEPS].finishReason).toBe("stop");
    for (const step of result.steps) {
      expect(step.usage.inputTokens).toBe(100);
      expect(step.usage.outputTokens).toBe(10);
    }

    // The win itself: zero serialized request-body bytes in step history,
    // both on the SDK result and in every callback view of each step.
    for (const step of result.steps) {
      expect(step.request.body).toBeUndefined();
    }
    expect(stepRequests).toEqual(Array(TOTAL_STEPS).fill(undefined));
    expect(
      result.steps.reduce(
        (n, step) =>
          n +
          (step.request.body
            ? Buffer.byteLength(JSON.stringify(step.request.body))
            : 0),
        0,
      ),
    ).toBe(0);

    // Callbacks fire once per step, awaited before the next request, and the
    // final callback sees every completed step.
    expect(usageCalls).toHaveLength(TOTAL_STEPS);
    for (let i = 0; i < TOTAL_STEPS; i++) {
      expect(usageCalls[i]).toEqual({
        model: MODEL,
        input: 100,
        output: 10,
        context: {
          sessionId: "ses_request_retention",
          stepSeq: i,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
        },
      });
    }
    expect(events).toEqual([
      ...Array.from({ length: TOTAL_STEPS }, (_, i) => [
        `fetch:${i}`,
        `step:${i}`,
      ]).flat(),
      "finish",
    ]);
    expect(finish.totalUsage).toMatchObject({
      inputTokens: 500,
      outputTokens: 50,
      totalTokens: 550,
    });
    expect(finish.text).toBe("done");
    expect(finish.steps).toHaveLength(TOTAL_STEPS);
    expect(finish.steps.every((step) => step.request.body === undefined)).toBe(
      true,
    );
    const messages = finish.responseMessages as ModelMessage[];
    expect(JSON.stringify(messages)).toContain(PAYLOAD);

    // Native capture still records every wire body as a completed attempt.
    expect(envelopes).toHaveLength(TOTAL_STEPS);
    for (const envelope of envelopes) {
      expect(envelope.attempt.lifecycle).toBe("completed");
    }
    for (let i = 0; i < TOTAL_STEPS; i++) {
      expect(nativeInput(envelopes[i])).toEqual(JSON.parse(wireBodies[i]));
    }
  });
});
