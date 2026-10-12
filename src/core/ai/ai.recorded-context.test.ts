// Recorded-context integration pins for the contextRecorder seam. These run
// the REAL AI SDK streamText loop against MockLanguageModelV3 — no mocked SDK
// callbacks — so ordering assertions prove provider-dispatch gates.
import { type ModelMessage, simulateReadableStream, stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { RunPersistenceError } from "../runtime/persistenceError";
import type { RunContextRecorder } from "../runtime/runContext";

const state: { model?: MockLanguageModelV3 } = {};
vi.mock("./utils", async () => ({
  ...(await vi.importActual<typeof import("./utils")>("./utils")),
  getProviderModel: () => state.model,
}));

const { streamResponse } = await import("./ai");

const MODEL = "claude-haiku-4-5";
const usage = {
  inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 5, text: 5, reasoning: undefined },
};

const PROBE_TOOL = {
  probe: {
    description: "probe",
    inputSchema: z.object({ q: z.string() }),
    execute: async () => "ok",
  },
};

interface Checkpoint {
  messages: ModelMessage[];
  system: string | null;
}

/** In-memory recorder: records commits, optional gates, exposes latest. */
function fakeRecorder(overrides: Partial<RunContextRecorder> = {}) {
  const checkpoints: Checkpoint[] = [];
  let committed: ModelMessage[] | undefined;
  let latched: RunPersistenceError | undefined;
  const recorder: RunContextRecorder = {
    checkpoint: async (input) => {
      checkpoints.push({
        messages: structuredClone(input.messages),
        system: input.system ?? null,
      });
      committed = structuredClone(input.messages);
    },
    flush: async () => {
      if (latched) throw latched;
    },
    latest: () => structuredClone(committed),
    ...overrides,
  };
  return {
    recorder,
    checkpoints,
    latch: (e: RunPersistenceError) => (latched = e),
  };
}

function textStepChunks(id: string, text: string) {
  return [
    { type: "text-start" as const, id },
    { type: "text-delta" as const, id, delta: text },
    { type: "text-end" as const, id },
  ];
}

function finishChunk() {
  return {
    type: "finish" as const,
    finishReason: { unified: "stop" as const, raw: "stop" },
    usage,
  };
}

function toolCallChunk() {
  return {
    type: "tool-call" as const,
    toolCallId: "c1",
    toolName: "probe",
    input: '{"q":"x"}',
  };
}

import type { LanguageModelV3StreamResult } from "@ai-sdk/provider";

function streamOf(chunks: unknown[]): LanguageModelV3StreamResult {
  return {
    stream: simulateReadableStream({ chunks: chunks as never }),
  } as LanguageModelV3StreamResult;
}

async function drain(stream: { fullStream: AsyncIterable<unknown> }) {
  for await (const _part of stream.fullStream) {
    /* consume the SDK lifecycle */
  }
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("pre-dispatch gate (real SDK)", () => {
  it("awaits the turn-0 checkpoint before the provider is called", async () => {
    let releaseCheckpoint!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseCheckpoint = resolve;
    });
    let providerCalled = false;
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      doStream: async () => {
        providerCalled = true;
        return streamOf([...textStepChunks("t0", "hi"), finishChunk()]);
      },
    });
    const { recorder, checkpoints } = fakeRecorder({
      checkpoint: async (input) => {
        checkpoints.push({
          messages: structuredClone(input.messages),
          system: input.system ?? null,
        });
        await gate;
      },
    });

    const consumed = drain(
      streamResponse({
        model: MODEL,
        prompt: "hello",
        silent: true,
        contextRecorder: recorder,
      }),
    );
    await vi.waitFor(() => expect(checkpoints.length).toBe(1));
    await new Promise((r) => setTimeout(r, 25));
    expect(providerCalled).toBe(false);
    releaseCheckpoint();
    await consumed;
    expect(providerCalled).toBe(true);
  });

  it("commit failure prevents dispatch and fails the run", async () => {
    let providerCalled = false;
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      doStream: async () => {
        providerCalled = true;
        return streamOf([...textStepChunks("t0", "hi"), finishChunk()]);
      },
    });
    const { recorder } = fakeRecorder({
      checkpoint: async () => {
        throw new RunPersistenceError(new Error("disk full"));
      },
    });

    await expect(
      drain(
        streamResponse({
          model: MODEL,
          prompt: "hello",
          silent: true,
          contextRecorder: recorder,
        }),
      ),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    expect(providerCalled).toBe(false);
  });
});

describe("step commits (real SDK)", () => {
  it("commits base + cumulative response.messages per step, preserving accepted outputs in later turns", async () => {
    let call = 0;
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      doStream: async () => {
        call++;
        if (call === 1) {
          return streamOf([toolCallChunk(), finishChunk()]);
        }
        return streamOf([...textStepChunks("t1", "done"), finishChunk()]);
      },
    });
    const { recorder, checkpoints } = fakeRecorder();

    await drain(
      streamResponse({
        model: MODEL,
        prompt: "run the probe",
        silent: true,
        tools: PROBE_TOOL,
        stopWhen: stepCountIs(2),
        contextRecorder: recorder,
      }),
    );

    // turn-0 gate, step-0 commit, turn-1 gate, step-1 commit.
    expect(checkpoints.length).toBe(4);
    // Turn 0: the prompt as the initial user message (SDK-normalized string content).
    expect(checkpoints[0].messages).toEqual([
      { role: "user", content: "run the probe" },
    ]);
    // Turn-1 gate: full context INCLUDING the accepted tool exchange — the
    // deleted-outputs bug this pins against.
    expect(checkpoints[2].messages.length).toBe(3);
    expect(checkpoints[2].messages[1].role).toBe("assistant");
    expect(checkpoints[2].messages[2].role).toBe("tool");
    // Step-0 commit (index 1) equals the turn-1 gate commit (index 2).
    expect(checkpoints[1].messages).toEqual(checkpoints[2].messages);
    // Step-1 commit: prior context + final assistant text.
    expect(checkpoints[3].messages.length).toBe(4);
    expect(checkpoints.every((c) => c.system === null)).toBe(true);
  });

  it("recorder.latest() read INSIDE the second doStream contains the prior tool exchange", async () => {
    let call = 0;
    const seenLatest: (ModelMessage[] | undefined)[] = [];
    const { recorder } = fakeRecorder();
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      doStream: async () => {
        call++;
        // Committed context at the SECOND provider dispatch — a
        // final-snapshot-only assertion misses per-turn deletion bugs.
        if (call === 2) seenLatest.push(recorder.latest());
        if (call === 1) {
          return streamOf([toolCallChunk(), finishChunk()]);
        }
        return streamOf([...textStepChunks("t1", "done"), finishChunk()]);
      },
    });

    await drain(
      streamResponse({
        model: MODEL,
        prompt: "run the probe",
        silent: true,
        tools: PROBE_TOOL,
        stopWhen: stepCountIs(2),
        contextRecorder: recorder,
      }),
    );

    const atSecondDispatch = seenLatest[0];
    expect(atSecondDispatch).toBeDefined();
    expect(atSecondDispatch?.length).toBe(3);
    expect(atSecondDispatch?.[1]?.role).toBe("assistant");
    expect(atSecondDispatch?.[2]?.role).toBe("tool");
  });

  it("next step is blocked after a failed step commit (SDK swallows the callback error)", async () => {
    let latched: RunPersistenceError | undefined;
    let call = 0;
    let providerCalls = 0;
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      doStream: async () => {
        providerCalls++;
        call++;
        if (call === 1) {
          return streamOf([toolCallChunk(), finishChunk()]);
        }
        return streamOf([...textStepChunks("t1", "never"), finishChunk()]);
      },
    });
    const { recorder } = fakeRecorder({
      checkpoint: async (input) => {
        if (input.messages.length > 1) {
          latched ??= new RunPersistenceError(new Error("step write failed"));
          throw latched;
        }
      },
      flush: async () => {
        if (latched) throw latched;
      },
    });

    // Step-0's commit rejects inside the swallowed onStepFinish; turn 1's
    // prepareStep gate rethrows the latch before dispatching.
    await expect(
      drain(
        streamResponse({
          model: MODEL,
          prompt: "run the probe",
          silent: true,
          tools: PROBE_TOOL,
          stopWhen: stepCountIs(2),
          contextRecorder: recorder,
        }),
      ),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    expect(providerCalls).toBe(1);
  });
});

describe("cached system prompt (Claude) (real SDK)", () => {
  const CASES: Array<{ label: string; model: string; withSystem: boolean }> = [
    {
      label: "uncached model: system stays a top-level system",
      model: "claude-haiku-4-5",
      withSystem: false,
    },
    {
      label: "cached Anthropic: system null and one embedded system message",
      model: "claude-sonnet-4-5",
      withSystem: true,
    },
  ];

  it.each(CASES)("$label", async ({ model, withSystem }) => {
    state.model = new MockLanguageModelV3({
      modelId: model,
      doStream: async () =>
        streamOf([...textStepChunks("t0", "ok"), finishChunk()]),
    });
    const { recorder, checkpoints } = fakeRecorder();

    await drain(
      streamResponse({
        model,
        prompt: "hello",
        system: withSystem ? "You are a test." : undefined,
        silent: true,
        contextRecorder: recorder,
      }),
    );

    for (const c of checkpoints) {
      if (withSystem) {
        expect(c.system).toBeNull();
        expect(c.messages[0]).toMatchObject({ role: "system" });
      } else {
        expect(c.system).toBeNull();
        expect(c.messages.some((m) => m.role === "system")).toBe(false);
      }
    }
  });
});

describe("critical failure modes (real SDK)", () => {
  it("reactive fit: summary epoch committed before the retried dispatch", async () => {
    let call = 0;
    const latestAtDispatch: (ModelMessage[] | undefined)[] = [];
    const { recorder, checkpoints } = fakeRecorder();
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      // summarizeConversation runs generateText (doGenerate) for the summary.
      doGenerate: async () => ({
        content: [{ type: "text", text: "A compact summary" }],
        finishReason: { unified: "stop", raw: "stop" },
        usage,
        warnings: [],
      }),
      doStream: async () => {
        call++;
        if (call === 1) {
          const err = new Error(
            "prompt is too long: 999999 tokens > 12 maximum",
          );
          return {
            stream: simulateReadableStream({
              chunks: [{ type: "error", error: err } as never],
            }),
          };
        }
        // Committed context AT the retried dispatch — the summary epoch
        // must already be durable here, not just in the final snapshot.
        latestAtDispatch.push(recorder.latest());
        return streamOf([...textStepChunks("t1", "ok"), finishChunk()]);
      },
    });

    await drain(
      streamResponse({
        model: MODEL,
        prompt: "start",
        silent: true,
        contextRecorder: recorder,
      }),
    );

    const atRetry = latestAtDispatch[0];
    expect(atRetry).toBeDefined();
    const serialized = JSON.stringify(atRetry);
    expect(serialized).toContain("start");
    expect(serialized).toContain("summary");
    expect(checkpoints.length).toBeGreaterThanOrEqual(2);
  });

  it("tool-repair synthetic event does not duplicate the base in canonical commits", async () => {
    let repairGenerateCalls = 0;
    const { recorder, checkpoints } = fakeRecorder();
    state.model = new MockLanguageModelV3({
      modelId: MODEL,
      // experimental_repairToolCall runs generateText for corrected args.
      doGenerate: async () => {
        repairGenerateCalls++;
        return {
          content: [{ type: "text", text: '{"q":"fixed"}' }],
          finishReason: { unified: "stop", raw: "stop" },
          usage,
          warnings: [],
        };
      },
      // Invalid input (q must be a string, not a number) forces the repair
      // path; the SDK passes tool-call input as a JSON string.
      doStream: async () =>
        streamOf([
          {
            type: "tool-call",
            toolCallId: "c1",
            toolName: "probe",
            input: '{"q": 123}',
          },
          finishChunk(),
        ]),
    });

    await drain(
      streamResponse({
        model: MODEL,
        prompt: "run the probe",
        silent: true,
        tools: PROBE_TOOL,
        contextRecorder: recorder,
      }),
    );

    // The repair actually ran — the regression path executed.
    expect(repairGenerateCalls).toBe(1);
    // Every commit is the base optionally extended, never base + base.
    const base = checkpoints[0]?.messages ?? [];
    expect(base.length).toBeGreaterThan(0);
    for (const c of checkpoints) {
      expect(c.messages.slice(0, base.length)).toEqual(base);
      expect(c.messages.slice(base.length, base.length * 2)).not.toEqual(base);
    }
  });
});
