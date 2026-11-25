import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { wrapLanguageModel } from "ai";
import { afterEach, expect, it, vi } from "vitest";
import { createCustomModel } from "../../ai/providers/custom";
import { AgentEventBus, type AgentEventMap } from "../../eventBus";
import { basetenStartup } from "./basetenStartup";
import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";

afterEach(() => vi.unstubAllGlobals());

it.each([
  ["text", "ready"],
  ["reasoning", "ready"],
  ["tool", "ready"],
  ["abort", "cancelled"],
  ["error", "failed"],
  ["empty", "finished"],
] as const)(
  "tracks a Baseten request through its first %s event",
  async (kind, expectedStatus) => {
    const rootPath = mkdtempSync(join(tmpdir(), "apex-baseten-wait-"));
    const gate = new AbortController();
    const body = new TransformStream<Uint8Array, Uint8Array>();
    const writer = body.writable.getWriter();
    const fetch = vi.fn(
      async () =>
        new Response(body.readable, {
          headers: { "content-type": "text/event-stream" },
        }),
    );
    vi.stubGlobal("fetch", fetch);
    const bus = new AgentEventBus();
    const events: AgentEventMap["model-loading"][] = [];
    bus.on("model-loading", (e) => events.push(e));
    bus.on("error", () => {});
    const model = "custom:research:nyx";
    const agent = new OffensiveSecurityAgent({
      session: {
        id: "ses_baseten_startup",
        version: "1.0.0",
        rootPath,
        logsPath: join(rootPath, "logs"),
        findingsPath: join(rootPath, "findings"),
        scratchpadPath: join(rootPath, "scratchpad"),
        pocsPath: join(rootPath, "pocs"),
        targets: [],
        time: { created: 0, updated: 0 },
      },
      prompt: "Hello",
      activeTools: [],
      eventBus: bus,
      abortSignal: gate.signal,
      model,
      authConfig: {
        customProviders: {
          research: {
            baseUrl:
              "https://model-test.api.baseten.co/deployment/example/sync/v1",
            models: [
              { id: "nyx", contextLength: 262144, maxOutputTokens: 32768 },
            ],
          },
        },
      },
    });
    const send = (delta: object, finish_reason: string | null = null) =>
      writer.write(
        new TextEncoder().encode(
          `data: ${JSON.stringify({ id: "test", model: "nyx", created: 0, choices: [{ index: 0, delta, finish_reason }] })}\n\n`,
        ),
      );
    const consume = agent.consume().catch((error: unknown) => error);
    try {
      await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce());
      await send({ role: "assistant", content: "" });
      await vi.waitFor(
        () => expect(events.map((e) => e.status)).toEqual(["loading"]),
        { timeout: 2500 },
      );
      expect(events[0]).toMatchObject({
        model,
        sessionId: "ses_baseten_startup",
        firstTokenStartedAt: expect.any(Number),
      });
      if (kind === "abort") {
        gate.abort();
        await writer.close().catch(() => {});
      } else if (kind === "empty") {
        await send({}, "stop");
        await writer.close();
      } else if (kind === "error") {
        await writer.abort(new Error("upstream disconnected"));
      } else {
        const delta =
          kind === "text"
            ? { content: "Hello" }
            : kind === "reasoning"
              ? { reasoning_content: "Thinking" }
              : {
                  tool_calls: [
                    {
                      index: 0,
                      id: "call1",
                      type: "function",
                      function: { name: "test_tool", arguments: "{}" },
                    },
                  ],
                };
        await send(delta);
        await vi.waitFor(() => expect(events.at(-1)?.status).toBe("ready"));
        await send({}, "stop");
        await writer.close();
      }
      const outcome = await consume;
      if (kind === "text" || kind === "reasoning")
        expect(outcome).toBeUndefined();
      expect(events.map((e) => e.status)).toEqual(["loading", expectedStatus]);
      expect(events[1].firstTokenStartedAt).toBe(events[0].firstTokenStartedAt);
      expect(fetch).toHaveBeenCalledTimes(1);
    } finally {
      gate.abort();
      await writer.abort().catch(() => {});
      await consume;
      rmSync(rootPath, { recursive: true, force: true });
    }
  },
  8_000,
);

it("waits for provider cancellation before releasing the request", async () => {
  const cleanup = Promise.withResolvers<void>();
  const cancel = vi.fn(() => cleanup.promise);
  const report = vi.fn();
  const deployment = createCustomModel("custom:research:nyx", {
    research: {
      baseUrl: "https://model-test.api.baseten.co/deployment/example/sync/v1",
      models: [{ id: "nyx", contextLength: 262144, maxOutputTokens: 32768 }],
    },
  });
  vi.spyOn(deployment, "doStream").mockResolvedValue({
    stream: new ReadableStream({ cancel }),
  });
  const model = wrapLanguageModel({
    model: deployment,
    middleware: basetenStartup("nyx", report),
  });
  const { stream } = await model.doStream({ prompt: [] });
  const released = vi.fn();
  const stopped = stream.cancel("stop").then(released);
  await vi.waitFor(() => expect(cancel).toHaveBeenCalledWith("stop"));
  expect(released).not.toHaveBeenCalled();
  cleanup.resolve();
  await stopped;
  expect(report).not.toHaveBeenCalled();
});
