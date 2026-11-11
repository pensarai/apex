import { AsyncLocalStorage } from "node:async_hooks";
import { simulateReadableStream, streamText, type ToolSet } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { expect, it, vi } from "vitest";
import { z } from "zod";
import { AgentEventBus } from "../../eventBus";
import { wrapToolExecutionContext } from "./toolExecutionContext";
import { ToolLifecycleTracker } from "./toolLifecycle";

it("establishes context before tool work and preserves concurrent tool identities", async () => {
  const scope = new AsyncLocalStorage<string>();
  const order: string[] = [];
  const execute = vi.fn(async (_input, options) => {
    expect(scope.getStore()).toBe(options.toolCallId);
    await new Promise((resolve) => setImmediate(resolve));
    expect(scope.getStore()).toBe(options.toolCallId);
    return options.toolCallId;
  });
  const conversion = vi.fn();
  const tools = wrapToolExecutionContext(
    { probe: { execute, toModelOutput: conversion } } as unknown as ToolSet,
    {
      run(call, body) {
        order.push(call.toolCallId);
        return scope.run(call.toolCallId, body);
      },
    },
  );
  const run = tools.probe!.execute!;
  expect(
    await Promise.all(
      ["first", "second"].map((toolCallId) =>
        collect(
          run(
            {},
            {
              context: {},
              toolCallId,
              messages: [],
            },
          ),
        ),
      ),
    ),
  ).toEqual([["first"], ["second"]]);
  expect(order).toEqual(["first", "second"]);
  expect(tools.probe!.toModelOutput).toBe(conversion);
});

it("lets the host reject a tool before any effect", async () => {
  const execute = vi.fn();
  const tools = wrapToolExecutionContext(
    { probe: { execute } } as unknown as ToolSet,
    {
      async run() {
        throw new Error("blocked");
      },
    },
  );
  await expect(
    collect(
      tools.probe!.execute!(
        {},
        {
          context: {},
          toolCallId: "call",
          messages: [],
        },
      ),
    ),
  ).rejects.toThrow("blocked");
  expect(execute).not.toHaveBeenCalled();
});

async function collect(output: unknown): Promise<unknown[]> {
  if (output && typeof output === "object" && Symbol.asyncIterator in output) {
    const values: unknown[] = [];
    for await (const value of output as AsyncIterable<unknown>)
      values.push(value);
    return values;
  }
  return [await output];
}

it.each([
  "scalar",
  "streaming",
] as const)("keeps %s SDK progress out of completion events and recovery state", async (kind) => {
  const scope = new AsyncLocalStorage<string>();
  const calls: string[] = [];
  const tools = wrapToolExecutionContext(
    {
      probe: {
        inputSchema: z.object({}),
        execute(_input, options) {
          if (kind === "scalar") {
            return (async () => {
              expect(scope.getStore()).toBe(options.toolCallId);
              calls.push(options.toolCallId);
              await new Promise((resolve) => setImmediate(resolve));
              expect(scope.getStore()).toBe(options.toolCallId);
              return "done";
            })();
          }
          return (async function* () {
            expect(scope.getStore()).toBe(options.toolCallId);
            calls.push(options.toolCallId);
            yield "working";
            await new Promise((resolve) => setImmediate(resolve));
            expect(scope.getStore()).toBe(options.toolCallId);
            yield "done";
          })();
        },
      },
    },
    { run: (call, execute) => scope.run(call.toolCallId, execute) },
  );
  const model = new MockLanguageModelV3({
    doStream: async () => ({
      stream: simulateReadableStream({
        chunks: [
          { type: "stream-start", warnings: [] },
          {
            type: "tool-call",
            toolCallId: "stream-call",
            toolName: "probe",
            input: "{}",
          },
          {
            type: "finish",
            finishReason: { unified: "tool-calls", raw: "tool_calls" },
            usage: {
              inputTokens: {
                total: 1,
                noCache: 1,
                cacheRead: 0,
                cacheWrite: 0,
              },
              outputTokens: { total: 1, text: 1, reasoning: 0 },
            },
          },
        ],
      }),
    }),
  });
  const results = [];
  const tracker = new ToolLifecycleTracker();
  const bus = new AgentEventBus();
  const completions: unknown[] = [];
  bus.on("tool-result", (event) => completions.push(event));
  for await (const part of streamText({ model, tools, prompt: "probe" })
    .fullStream) {
    tracker.observePart(part);
    bus.emitStreamPart(part, {
      sessionId: "session",
      messageId: "message",
      toolPartId: () => "part",
    });
    if (part.type === "tool-result" && part.preliminary) {
      expect(completions).toHaveLength(0);
      expect(tracker.snapshot().completedResults).toHaveLength(0);
      expect(tracker.inFlightTools.has("stream-call")).toBe(true);
    }
    if (part.type === "tool-result")
      results.push({
        output: part.output,
        preliminary: part.preliminary === true,
      });
    if (part.type === "error") throw part.error;
  }
  expect(calls).toEqual(["stream-call"]);
  expect(tracker.snapshot().completedResults).toEqual([
    {
      type: "tool-result",
      toolCallId: "stream-call",
      toolName: "probe",
      output: "done",
    },
  ]);
  expect(results).toEqual([
    ...(kind === "streaming" ? [{ output: "working", preliminary: true }] : []),
    { output: "done", preliminary: true },
    { output: "done", preliminary: false },
  ]);
  expect(completions).toEqual([
    {
      toolCallId: "stream-call",
      toolName: "probe",
      result: "done",
      sessionId: "session",
      messageId: "message",
      partId: "part",
    },
  ]);
  expect(scope.getStore()).toBeUndefined();
});

it("closes a partially consumed generator inside its host context", async () => {
  const scope = new AsyncLocalStorage<string>();
  const closed = vi.fn();
  const tools = wrapToolExecutionContext(
    {
      probe: {
        inputSchema: z.object({}),
        async *execute() {
          try {
            yield "partial";
            yield "final";
          } finally {
            await Promise.resolve();
            closed(scope.getStore());
          }
        },
      },
    },
    { run: (call, execute) => scope.run(call.toolCallId, execute) },
  );
  const output = tools.probe!.execute!(
    {},
    {
      context: {},
      toolCallId: "cancelled",
      messages: [],
    },
  ) as AsyncIterable<unknown>;
  for await (const value of output) {
    expect(value).toBe("partial");
    break;
  }
  expect(closed).toHaveBeenCalledWith("cancelled");
});

it("propagates an iterator failure with the host identity intact", async () => {
  const scope = new AsyncLocalStorage<string>();
  const tools = wrapToolExecutionContext(
    {
      probe: {
        inputSchema: z.object({}),
        async *execute() {
          yield "partial";
          await Promise.resolve();
          expect(scope.getStore()).toBe("failed");
          throw new Error("stream failed");
        },
      },
    },
    { run: (call, execute) => scope.run(call.toolCallId, execute) },
  );
  await expect(
    collect(
      tools.probe!.execute!(
        {},
        {
          context: {},
          toolCallId: "failed",
          messages: [],
        },
      ),
    ),
  ).rejects.toThrow("stream failed");
});

it("finishes the scope only after a yielding generator finalizer drains", async () => {
  const scope = new AsyncLocalStorage<string>();
  const events: string[] = [];
  const tools = wrapToolExecutionContext(
    {
      probe: {
        inputSchema: z.object({}),
        async *execute() {
          try {
            yield "partial";
          } finally {
            expect(scope.getStore()).toBe("returning");
            events.push("closing");
            yield "cleanup progress";
            await Promise.resolve();
            expect(scope.getStore()).toBe("returning");
            events.push("drained");
          }
        },
      },
    },
    {
      run: (call, execute) => scope.run(call.toolCallId, execute),
      async finish(call) {
        expect(call.toolCallId).toBe("returning");
        events.push("finished");
      },
    },
  );
  for await (const value of tools.probe!.execute!(
    {},
    {
      context: {},
      toolCallId: "returning",
      messages: [],
    },
  ) as AsyncIterable<unknown>) {
    expect(value).toBe("partial");
    break;
  }
  expect(events).toEqual(["closing", "drained", "finished"]);
});

it.each([
  "execute",
  "iterator",
  "next",
] as const)("closes the host scope when %s throws", async (phase) => {
  const finish = vi.fn(async () => {});
  const failure = new Error(`failed ${phase}`);
  const tools = wrapToolExecutionContext(
    {
      probe: {
        inputSchema: z.object({}),
        execute() {
          if (phase === "execute") throw failure;
          return {
            [Symbol.asyncIterator]() {
              if (phase === "iterator") throw failure;
              return {
                next: async () => {
                  throw failure;
                },
              };
            },
          };
        },
      },
    },
    { run: (_call, execute) => execute(), finish },
  );
  await expect(
    collect(
      tools.probe!.execute!(
        {},
        {
          context: {},
          toolCallId: "failed",
          messages: [],
        },
      ),
    ),
  ).rejects.toBe(failure);
  expect(finish).toHaveBeenCalledOnce();
  expect(finish).toHaveBeenCalledWith({
    toolCallId: "failed",
    toolName: "probe",
  });
});

it.each([
  "execute",
  "return",
] as const)("preserves %s and distinct finish errors", async (phase) => {
  const original = new Error("original");
  const cleanup = new Error("cleanup");
  const tools = wrapToolExecutionContext(
    {
      probe: {
        inputSchema: z.object({}),
        execute() {
          if (phase === "execute") throw original;
          return {
            [Symbol.asyncIterator]: () => ({
              next: async () => ({ done: false, value: "partial" }),
              return: async () => {
                throw original;
              },
            }),
          };
        },
      },
    },
    {
      run: (_call, body) => body(),
      finish: async () => {
        throw cleanup;
      },
    },
  );
  const iterator = tools.probe!.execute!(
    {},
    {
      context: {},
      toolCallId: "call",
      messages: [],
    },
  ) as AsyncGenerator;
  if (phase === "return") await iterator.next();
  const result =
    phase === "execute" ? iterator.next() : iterator.return(undefined);
  await expect(result).rejects.toMatchObject({ errors: [original, cleanup] });
});

it("preserves a repeated failure's identity and rejects work before execution", async () => {
  const failure = new Error("aborted");
  const execute = vi.fn();
  const tools = wrapToolExecutionContext(
    { probe: { execute } } as unknown as ToolSet,
    {
      run: async () => {
        throw failure;
      },
      finish: async () => {
        throw failure;
      },
    },
  );
  await expect(
    collect(
      tools.probe!.execute!(
        {},
        {
          context: {},
          toolCallId: "call",
          messages: [],
        },
      ),
    ),
  ).rejects.toBe(failure);
  expect(execute).not.toHaveBeenCalled();
});

it("does not enter a generator aborted during acquisition, but still closes it", async () => {
  const abort = new AbortController();
  const failure = new Error("cancelled before first next");
  const body = vi.fn();
  const close = vi.fn(async () => ({ done: true, value: undefined }));
  const finish = vi.fn(async () => {});
  const tools = wrapToolExecutionContext(
    {
      probe: {
        inputSchema: z.object({}),
        execute() {
          return {
            [Symbol.asyncIterator]() {
              abort.abort(failure);
              return {
                next: async () => {
                  body();
                  return { done: false, value: "bad" };
                },
                return: close,
              };
            },
          };
        },
      },
    },
    { run: (_call, execute) => execute(), finish },
  );
  await expect(
    collect(
      tools.probe!.execute!(
        {},
        {
          context: {},
          toolCallId: "call",
          messages: [],
          abortSignal: abort.signal,
        },
      ),
    ),
  ).rejects.toBe(failure);
  expect(body).not.toHaveBeenCalled();
  expect(close).toHaveBeenCalledOnce();
  expect(finish).toHaveBeenCalledOnce();
});
