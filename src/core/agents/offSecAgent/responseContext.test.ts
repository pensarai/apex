import { AsyncLocalStorage } from "node:async_hooks";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ToolSet } from "ai";
import { afterEach, expect, it, vi } from "vitest";
import { z } from "zod";
import type { SessionInfo } from "../../session";
import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";

const mock = vi.hoisted(() => ({ streamResponse: vi.fn() }));
vi.mock("../../ai", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  streamResponse: mock.streamResponse,
}));

const owner = new AsyncLocalStorage<string>();
const scope = new AsyncLocalStorage<string>();
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
  vi.clearAllMocks();
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function fixture(
  options: {
    cold?: boolean;
    calls?: number;
    error?: "sync" | "async";
    early?: boolean;
    custom?: boolean;
    structured?: boolean;
  } = {},
) {
  const root = mkdtempSync(join(tmpdir(), "response-context-"));
  roots.push(root);
  const response = deferred<{ messages: [] }>();
  const drain = deferred<void>();
  const closed: string[] = [];
  const resolved: Array<{
    value: unknown;
    owner: string | undefined;
    scope: string | undefined;
  }> = [];
  const failure = new Error("fixture resolver failure");
  const calls = options.calls ?? 1;
  mock.streamResponse.mockImplementation(({ tools }: { tools: ToolSet }) => ({
    response: response.promise,
    fullStream: (async function* () {
      yield { type: "start" };
      for (let index = 0; index < calls; index++) {
        const toolCallId = `response-${index}`;
        const execute = tools.response?.execute;
        if (!execute) throw new Error("Missing response tool");
        const output = execute(
          { result: `value-${index}` },
          {
            context: {},
            toolCallId,
            messages: [],
          },
        );
        for await (const _ of output as AsyncIterable<unknown>) {
          /* Drain the real response wrapper. */
        }
      }
      expect(closed).toHaveLength(calls);
      response.resolve({ messages: [] });
      if (options.early) await drain.promise;
    })(),
  }));
  const resolveResult = (
    stream: { response: PromiseLike<unknown> },
    value?: unknown,
  ) => {
    if (options.error === "sync") throw failure;
    return (async () => {
      await stream.response;
      if (options.error === "async") throw failure;
      resolved.push({
        value,
        owner: owner.getStore(),
        scope: scope.getStore(),
      });
      return z.string().parse(value ?? "fallback");
    })();
  };
  const agent = owner.run(
    "constructor",
    () =>
      new OffensiveSecurityAgent<string>({
        session: {
          id: "ses_response_context",
          version: "1.0.0",
          targets: [],
          time: { created: 1, updated: 1 },
          rootPath: root,
          logsPath: join(root, "logs"),
          findingsPath: join(root, "findings"),
          scratchpadPath: join(root, "scratchpad"),
          pocsPath: join(root, "pocs"),
          config: {},
        } as SessionInfo,
        model: "fixture-model",
        prompt: "Finish the fixture",
        toolProtocol: "direct",
        activeTools: [],
        ...(options.structured === false ? {} : { responseSchema: z.string() }),
        ...(options.custom === false ? {} : { resolveResult }),
        toolExecutionContext: {
          run: (call, execute) => scope.run(`tool:${call.toolCallId}`, execute),
          finish: async (call) => {
            closed.push(call.toolCallId);
          },
        },
      }),
  );
  if (options.cold)
    owner.run("stream-owner", () => {
      void agent.streamResult;
    });
  return {
    agent,
    closed,
    resolved,
    failure,
    drain,
    consume: () =>
      owner.run(options.cold ? "consumer" : "stream-owner", () =>
        agent.consume(),
      ),
  };
}

it.each([
  false,
  true,
])("resolves after response closure in the stream owner context (cold=%s)", async (cold) => {
  const f = fixture({ cold });
  await expect(f.consume()).resolves.toBe("value-0");
  await f.agent.drained;
  expect(f.closed).toEqual(["response-0"]);
  expect(f.resolved).toEqual([
    { value: "value-0", owner: "stream-owner", scope: undefined },
  ]);
});

it.each([
  "sync",
  "async",
] as const)("propagates %s resolver errors to capture and consume", async (error) => {
  const f = fixture({ error });
  const captured = expect(f.agent.responseCaptured).rejects.toBe(f.failure);
  await expect(f.consume()).rejects.toBe(f.failure);
  await captured;
  await f.agent.drained;
});

it("rejects a structured run without a response call", async () => {
  const f = fixture({ calls: 0 });
  await expect(f.consume()).rejects.toThrow(
    "Structured agent ses_response_context ended without a validated response",
  );
  await f.agent.drained;
  expect(f.resolved).toEqual([]);
});

it("preserves custom resolvers for non-structured runs", async () => {
  const f = fixture({ calls: 0, structured: false });
  await expect(f.consume()).resolves.toBe("fallback");
  await f.agent.drained;
  expect(f.resolved).toEqual([
    { value: undefined, owner: "stream-owner", scope: undefined },
  ]);
});

it("preserves early result capture before the stream drain", async () => {
  const f = fixture({ early: true });
  try {
    await expect(f.consume()).resolves.toBe("value-0");
    expect(f.resolved).toEqual([
      { value: "value-0", owner: "stream-owner", scope: undefined },
    ]);
  } finally {
    f.drain.resolve();
    await f.agent.drained;
  }
});

it("keeps the resolver invocation for each validated response", async () => {
  const f = fixture({ calls: 2 });
  await expect(f.consume()).resolves.toBe("value-0");
  await f.agent.drained;
  expect(f.resolved).toEqual(
    [0, 1].map((index) => ({
      value: `value-${index}`,
      owner: "stream-owner",
      scope: undefined,
    })),
  );
});

it("captures responses without a custom resolver", async () => {
  const f = fixture({ custom: false });
  await expect(f.consume()).resolves.toBe("value-0");
  await f.agent.drained;
  expect(f.closed).toEqual(["response-0"]);
});
