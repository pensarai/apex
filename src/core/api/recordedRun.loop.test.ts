import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";
import { simulateReadableStream } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RunLimitError } from "../runtime/runModelStore";
import { openSqliteRunStore } from "../runtime/sqliteRunStore";
import type { SessionInfo } from "../session";

const state: {
  model?: MockLanguageModelV3;
  sessionRoot: string;
  session?: SessionInfo;
} = { sessionRoot: "" };

vi.mock("../ai/utils", async () => ({
  ...(await vi.importActual<typeof import("../ai/utils")>("../ai/utils")),
  getProviderModel: () => state.model,
}));

// Keep the real agent, SDK loop, tools, and SQLite; isolate session storage.
vi.mock("../session", async () => ({
  ...(await vi.importActual<typeof import("../session")>("../session")),
  create: async (input: Parameters<typeof import("../session").create>[0]) => {
    if (!input.id || !input.name) throw new Error("Missing session identity");
    state.session = {
      id: input.id,
      version: "fixture",
      name: input.name,
      targets: input.targets ?? [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: state.sessionRoot,
      findingsPath: join(state.sessionRoot, "findings"),
      pocsPath: join(state.sessionRoot, "pocs"),
      logsPath: join(state.sessionRoot, "logs"),
      scratchpadPath: join(state.sessionRoot, "scratchpad"),
      config: input.config,
    } as SessionInfo;
    return state.session;
  },
  get: async () => state.session,
}));

const { runRecordedAgent, resumeRecordedAgent } = await import("./recordedRun");
type Store = Awaited<ReturnType<typeof openSqliteRunStore>>;
let store: Store;
let root: string;
let target: Server;
let targetUrl: string;
let hits: string[];

const usage = {
  inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 5, text: 5, reasoning: undefined },
};

function stream(chunks: LanguageModelV3StreamPart[]) {
  return { stream: simulateReadableStream({ chunks }) };
}

function httpStep(path: string) {
  return stream([
    {
      type: "tool-call",
      toolCallId: `tc_${path}`,
      toolName: "http_request",
      input: JSON.stringify({
        url: `${targetUrl}/${path}`,
        method: "GET",
        toolCallDescription: `Request ${path}`,
      }),
    },
    {
      type: "finish",
      finishReason: { unified: "tool-calls", raw: "tool_use" },
      usage,
    },
  ]);
}

function finalStep() {
  return stream([
    { type: "text-start", id: "summary" },
    { type: "text-delta", id: "summary", delta: "Both requests completed." },
    { type: "text-end", id: "summary" },
    {
      type: "finish",
      finishReason: { unified: "stop", raw: "end_turn" },
      usage,
    },
  ]);
}

function spec(runId: string, maxModelAttempts = 3) {
  return {
    schemaVersion: 1,
    configVersion: 1,
    runId,
    prompt: "Request /first, then /second in a separate turn, then summarize.",
    system: "Follow the user's requests.",
    target: targetUrl,
    model: "claude-haiku-4-5",
    activeTools: ["http_request"],
    environment: { kind: "local", cwd: root },
    scope: {
      version: 1,
      allowedHosts: ["127.0.0.1"],
      allowedPorts: [Number(new URL(targetUrl).port)],
      strictScope: true,
      allowDestructiveActions: false,
      allowRateLimitTesting: false,
    },
    credentialRefs: [],
    limits: { maxModelAttempts },
  };
}

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), "recorded-loop-"));
  state.sessionRoot = join(root, "session");
  state.session = undefined;
  for (const leaf of ["", "findings", "pocs", "logs", "scratchpad"]) {
    mkdirSync(join(state.sessionRoot, leaf), { recursive: true });
  }
  store = await openSqliteRunStore(join(root, "runs.sqlite"));
  hits = [];
  target = createServer((request, response) => {
    hits.push(request.url ?? "");
    response.end("ok");
  });
  await new Promise<void>((resolve) => target.listen(0, "127.0.0.1", resolve));
  const address = target.address();
  if (!address || typeof address === "string") throw new Error("No port");
  targetUrl = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  target.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    target.close((error) => (error ? reject(error) : resolve())),
  );
  store.close();
  rmSync(root, { recursive: true, force: true });
});

describe("recorded runs through the real agent and SDK loop", () => {
  it.each([
    false,
    true,
  ])("settles before pausing and resumes without repeating work (runtime facts: %s)", async (withRuntimeFacts) => {
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    target.removeAllListeners("request");
    target.on("request", async (request, response) => {
      hits.push(request.url ?? "");
      if (request.url === "/first") await held;
      response.end("ok");
    });
    const doStream = vi
      .fn()
      .mockImplementationOnce(async () => httpStep("first"))
      .mockImplementationOnce(async () => httpStep("second"))
      .mockImplementation(async () => finalStep());
    state.model = new MockLanguageModelV3({ doStream });
    const input = spec("run_pause_between_turns");
    if (withRuntimeFacts) input.activeTools.push("read_file");
    const running = runRecordedAgent({ spec: input, store });
    void running.catch(() => {});

    try {
      await vi.waitFor(() => expect(hits).toEqual(["/first"]));
      const client = await openSqliteRunStore(join(root, "runs.sqlite"));
      try {
        const control = await client.getControl(input.runId);
        if (!control) throw new Error("Missing run control");
        await client.requestControl(input.runId, "pause", control.revision);
      } finally {
        client.close();
      }
    } finally {
      release();
    }
    const paused = await running;
    expect(paused.record.status).toBe("paused");
    expect(hits).toEqual(["/first"]);
    expect(doStream).toHaveBeenCalledTimes(1);
    expect(await store.listToolOperations(input.runId)).toMatchObject([
      { toolCallId: "tc_first", state: "settled" },
    ]);
    expect(await store.listModelAttempts(input.runId)).toHaveLength(1);

    store.close();
    store = await openSqliteRunStore(join(root, "runs.sqlite"));
    const resumed = await resumeRecordedAgent({ runId: input.runId, store });

    expect(resumed.record.status).toBe("completed");
    expect(resumed.record.sessionId).toBe(paused.record.sessionId);
    expect(resumed.record.attemptId).not.toBe(paused.record.attemptId);
    expect(hits).toEqual(["/first", "/second"]);
    expect(doStream).toHaveBeenCalledTimes(3);
    const resumedSystem = state.model.doStreamCalls[1]?.prompt.find(
      (message) => message.role === "system",
    );
    expect(resumedSystem?.content.split("[BUNDLED ASSETS]")).toHaveLength(2);
    expect(resumedSystem?.content.split("[RUNTIME CONTEXT]")).toHaveLength(
      withRuntimeFacts ? 2 : 1,
    );
    expect(state.model.doStreamCalls[1]?.prompt).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          role: "tool",
          content: expect.arrayContaining([
            expect.objectContaining({
              type: "tool-result",
              toolCallId: "tc_first",
              output: {
                type: "json",
                value: expect.objectContaining({ success: true, body: "ok" }),
              },
            }),
          ]),
        }),
      ]),
    );
    expect(await store.listModelAttempts(input.runId)).toHaveLength(3);
    expect(await store.listToolOperations(input.runId)).toMatchObject([
      { toolCallId: "tc_first", state: "settled" },
      { toolCallId: "tc_second", state: "settled" },
    ]);
    expect(await resumed.result?.streamResult.text).toBe(
      "Both requests completed.",
    );
  });

  it("continues across tool turns to a final answer without duplicate admission", async () => {
    const doStream = vi
      .fn()
      .mockImplementationOnce(async () => httpStep("first"))
      .mockImplementationOnce(async () => httpStep("second"))
      .mockImplementation(async () => finalStep());
    state.model = new MockLanguageModelV3({ doStream });
    const input = spec("run_multiple_turns");

    const outcome = await runRecordedAgent({ spec: input, store });

    expect(hits).toEqual(["/first", "/second"]);
    expect(doStream).toHaveBeenCalledTimes(3);
    expect(outcome.record.status).toBe("completed");
    expect(await outcome.result?.streamResult.text).toBe(
      "Both requests completed.",
    );
    expect(await store.listModelAttempts(input.runId)).toHaveLength(3);
    expect(await store.getContext(input.runId)).toMatchObject({
      messages: expect.arrayContaining([
        expect.objectContaining({
          role: "assistant",
          content: expect.arrayContaining([
            { type: "text", text: "Both requests completed." },
          ]),
        }),
      ]),
    });
    expect(await runRecordedAgent({ spec: input, store })).toMatchObject({
      started: false,
      record: { status: "completed" },
    });
    expect(hits).toEqual(["/first", "/second"]);
    expect(doStream).toHaveBeenCalledTimes(3);
  });

  it("enforces the persisted request limit before continuing after a tool", async () => {
    const doStream = vi.fn(async () => httpStep("first"));
    state.model = new MockLanguageModelV3({ doStream });
    const input = spec("run_turn_limit", 1);

    await expect(runRecordedAgent({ spec: input, store })).rejects.toThrow(
      RunLimitError,
    );

    expect(hits).toEqual(["/first"]);
    expect(doStream).toHaveBeenCalledTimes(1);
    expect(await store.listModelAttempts(input.runId)).toHaveLength(1);
    expect(await store.get(input.runId)).toMatchObject({ status: "failed" });
  });
});
