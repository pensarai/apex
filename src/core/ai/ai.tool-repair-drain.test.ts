import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";
import { stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { inProcessSubagentSpawner } from "../agents/offSecAgent/subagentSpawner";
import { httpRequest } from "../agents/offSecAgent/tools/httpRequest";
import type { ToolContext } from "../agents/offSecAgent/tools/types";
import { ModelStreamDrainError } from "./modelStreamDrain";

const state = vi.hoisted(() => ({ model: undefined as unknown }));
vi.mock("./utils", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./utils")>()),
  getProviderModel: () => state.model,
}));
const { streamResponse } = await import("./ai");
const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: 0 },
};
const valid = {
  url: "https://example.com/",
  method: "GET",
  headers: "{}",
  body: "hello",
  toolCallDescription: "Read benign fixture",
};
function deferred() {
  let release!: () => void;
  const promise = new Promise<void>((r) => {
    release = r;
  });
  return { promise, release };
}
function fixture(
  options: {
    aware?: boolean;
    failure?: Error;
    malformed?: boolean;
    usageBarrier?: ReturnType<typeof deferred>;
  } = {},
) {
  const root = mkdtempSync(join(tmpdir(), "repair-drain-"));
  const barrier = deferred();
  const abort = new AbortController();
  const repairSignals: AbortSignal[] = [];
  let repairSettled = false,
    providerCalls = 0;
  const backend = vi.fn(async () => ({
    success: false,
    status: 404,
    statusText: "Not Found",
    headers: { "content-type": "text/plain" },
    body: "benign",
    url: valid.url,
    redirected: false,
  }));
  const tool = httpRequest({
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_repair",
      version: "1.0.0",
      time: { created: 0, updated: 0 },
      findingsPath: join(root, "findings"),
      scratchpadPath: join(root, "scratchpad"),
      pocsPath: join(root, "pocs"),
      targets: ["https://example.com"],
      rootPath: root,
      logsPath: join(root, "logs"),
    },
    target: "https://example.com",
    agentCwd: root,
    backends: { http: { request: backend } },
  } as unknown as ToolContext);
  const generate = vi.fn(async (params) => {
    repairSignals.push(params.abortSignal);
    try {
      await (options.aware
        ? Promise.race([
            barrier.promise,
            new Promise<never>((_, reject) =>
              params.abortSignal.addEventListener(
                "abort",
                () => reject(params.abortSignal.reason),
                { once: true },
              ),
            ),
          ])
        : barrier.promise);
      if (options.failure) throw options.failure;
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(options.malformed ? { invalid: true } : valid),
          },
        ],
        finishReason: { unified: "stop" as const, raw: "stop" },
        usage,
        warnings: [],
      };
    } finally {
      repairSettled = true;
    }
  });
  state.model = new MockLanguageModelV3({
    doGenerate: generate,
    doStream: async () => {
      providerCalls++;
      const input = JSON.stringify({ ...valid, method: "INVALID" });
      const parts: LanguageModelV3StreamPart[] =
        providerCalls === 1
          ? [
              {
                type: "tool-input-start",
                id: "call-1",
                toolName: "http_request",
              },
              { type: "tool-input-delta", id: "call-1", delta: input },
              { type: "tool-input-end", id: "call-1" },
              {
                type: "tool-call",
                toolCallId: "call-1",
                toolName: "http_request",
                input,
              },
            ]
          : [
              { type: "text-start", id: "done" },
              { type: "text-delta", id: "done", delta: "done" },
              { type: "text-end", id: "done" },
            ];
      return {
        stream: new ReadableStream({
          start(c) {
            for (const part of parts) c.enqueue(part);
            c.enqueue({
              type: "finish",
              finishReason: {
                unified: providerCalls === 1 ? "tool-calls" : "stop",
                raw: providerCalls === 1 ? "tool_use" : "stop",
              },
              usage,
            });
            c.close();
          },
        }),
      };
    },
  });
  const onStepFinish = vi.fn(async (event) => {
    if (event.response.id === "tool-repair")
      await options.usageBarrier?.promise;
  });
  const stream = streamResponse({
    model: "claude-haiku-4-5",
    prompt: "Read benign fixture",
    messages: [{ role: "user", content: "Read benign fixture" }],
    tools: { http_request: tool },
    stopWhen: stepCountIs(2),
    silent: true,
    abortSignal: abort.signal,
    onStepFinish,
  });
  const events: string[] = [];
  let consumerSettled = false;
  const consumed = (async () => {
    try {
      for await (const p of stream.fullStream) events.push(p.type);
    } finally {
      consumerSettled = true;
    }
  })();
  void consumed.catch(() => {});
  return {
    barrier,
    abort,
    repairSignals,
    generate,
    backend,
    events,
    consumed,
    onStepFinish,
    get providerCalls() {
      return providerCalls;
    },
    get repairSettled() {
      return repairSettled;
    },
    get consumerSettled() {
      return consumerSettled;
    },
    async cleanup() {
      barrier.release();
      options.usageBarrier?.release();
      abort.abort();
      await vi.advanceTimersByTimeAsync(0);
      await consumed.catch(() => {});
      rmSync(root, { recursive: true, force: true });
    },
  };
}
afterEach(() => vi.useRealTimers());
async function start(f: ReturnType<typeof fixture>) {
  await vi.advanceTimersByTimeAsync(0);
  expect(f.generate).toHaveBeenCalledOnce();
}
describe("attempt-owned tool repair", () => {
  it("joins ignored cancellation before continuation and suppresses late effects", async () => {
    vi.useFakeTimers();
    const f = fixture();
    try {
      await start(f);
      await vi.advanceTimersByTimeAsync(300001);
      expect(f.repairSignals[0]?.aborted).toBe(true);
      const first = f.repairSignals[0]?.reason;
      expect(first).toMatchObject({ name: "StreamIdleTimeoutError" });
      expect(f.providerCalls).toBe(1);
      expect(f.consumerSettled).toBe(false);
      expect(f.backend).not.toHaveBeenCalled();
      f.barrier.release();
      await vi.advanceTimersByTimeAsync(0);
      await f.consumed;
      expect(f.providerCalls).toBe(2);
      expect(f.repairSettled).toBe(true);
      expect(f.backend).not.toHaveBeenCalled();
      expect(f.repairSignals[0]?.reason).toBe(first);
      expect(
        f.onStepFinish.mock.calls.filter(
          ([e]) => e.response.id === "tool-repair",
        ),
      ).toHaveLength(0);
    } finally {
      await f.cleanup();
    }
  });
  it("cancels an abort-aware repair before continuing", async () => {
    vi.useFakeTimers();
    const f = fixture({ aware: true });
    try {
      await start(f);
      await vi.advanceTimersByTimeAsync(300001);
      await f.consumed;
      expect(f.repairSettled).toBe(true);
      expect(f.providerCalls).toBe(2);
      expect(f.backend).not.toHaveBeenCalled();
    } finally {
      await f.cleanup();
    }
  });
  it("fails closed when a repair never confirms drain", async () => {
    vi.useFakeTimers();
    const f = fixture();
    try {
      await start(f);
      await vi.advanceTimersByTimeAsync(330001);
      await expect(f.consumed).rejects.toMatchObject({
        name: "ModelStreamDrainTimeoutError",
      });
      expect(f.providerCalls).toBe(1);
      expect(f.backend).not.toHaveBeenCalled();
      f.barrier.release();
      await vi.advanceTimersByTimeAsync(0);
      expect(f.backend).not.toHaveBeenCalled();
    } finally {
      await f.cleanup();
    }
  });
  it("joins caller cancellation even when the SDK ends normally", async () => {
    vi.useFakeTimers();
    const f = fixture();
    try {
      await start(f);
      const reason = new Error("caller stopped");
      f.abort.abort(reason);
      await vi.advanceTimersByTimeAsync(0);
      expect(f.repairSignals[0]?.reason).toBe(reason);
      expect(f.consumerSettled).toBe(false);
      expect(f.providerCalls).toBe(1);
      f.barrier.release();
      await vi.advanceTimersByTimeAsync(0);
      await f.consumed.catch(() => {});
      expect(f.consumerSettled).toBe(true);
      expect(f.backend).not.toHaveBeenCalled();
      expect(f.providerCalls).toBe(1);
    } finally {
      await f.cleanup();
    }
  });
  it("includes repair usage callbacks in the owned lifetime", async () => {
    vi.useFakeTimers();
    const usageBarrier = deferred();
    const f = fixture({ usageBarrier });
    try {
      await start(f);
      f.barrier.release();
      await vi.advanceTimersByTimeAsync(0);
      expect(f.onStepFinish).toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(300001);
      expect(f.providerCalls).toBe(1);
      usageBarrier.release();
      await vi.advanceTimersByTimeAsync(0);
      await f.consumed;
      expect(f.backend).not.toHaveBeenCalled();
      expect(f.providerCalls).toBe(2);
    } finally {
      await f.cleanup();
    }
  });
  it.each([
    "valid",
    "malformed",
    "provider-error",
  ] as const)("preserves ordinary %s repair settlement", async (mode) => {
    vi.useFakeTimers();
    const f = fixture({
      malformed: mode === "malformed",
      failure:
        mode === "provider-error"
          ? new Error("synthetic rejection")
          : undefined,
    });
    try {
      await start(f);
      f.barrier.release();
      await vi.advanceTimersByTimeAsync(0);
      await f.consumed;
      expect(f.providerCalls).toBe(2);
      expect(f.backend).toHaveBeenCalledTimes(mode === "valid" ? 1 : 0);
      expect(f.events).toContain(
        mode === "valid" ? "tool-result" : "tool-error",
      );
      expect(f.events.filter((e) => e === "finish-step")).toHaveLength(2);
    } finally {
      await f.cleanup();
    }
  });
  it.each([
    "ModelStreamDrainError",
    "ModelStreamDrainTimeoutError",
  ] as const)("does not swallow %s from repair", async (name) => {
    vi.useFakeTimers();
    const marker =
      name === "ModelStreamDrainError"
        ? new ModelStreamDrainError(new Error("unconfirmed"))
        : Object.assign(new Error("unconfirmed"), { name });
    const wrapped = new Error("recorder wrapper", { cause: marker });
    const f = fixture({ failure: wrapped });
    try {
      await start(f);
      f.barrier.release();
      await vi.advanceTimersByTimeAsync(0);
      await expect(f.consumed).rejects.toBe(wrapped);
      expect(f.providerCalls).toBe(1);
      expect(f.backend).not.toHaveBeenCalled();
    } finally {
      await f.cleanup();
    }
  });
});
