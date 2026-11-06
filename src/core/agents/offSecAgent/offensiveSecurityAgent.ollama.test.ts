import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AgentEventBus, type AgentEventMap } from "../../eventBus";
import type { OllamaCatalog } from "../../ollama";
import type { SessionInfo } from "../../session";
import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";

const name = "hf.co/webAI-Official/TwIL-8B:TwIL-8B-Q4_K_M-balanced.gguf";
const model = `ollama:${name}`;
const cleanups: (() => Promise<void> | void)[] = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

async function fixture({
  warm = false,
  stale = false,
  psSupported = true,
} = {}) {
  let loaded = warm;
  let pendingLoad: ServerResponse | undefined;
  const requests: { url: string; body?: Record<string, unknown> }[] = [];
  const server = createServer(async (req, res) => {
    res.setHeader("Content-Type", "application/json");
    const request: (typeof requests)[number] = { url: req.url ?? "" };
    requests.push(request);
    if (req.url === "/api/ps") {
      res.statusCode = psSupported ? 200 : 404;
      res.end(
        JSON.stringify({
          models: loaded ? [{ name, context_length: 32_768 }] : [],
        }),
      );
      return;
    }
    let body = "";
    for await (const chunk of req) body += chunk;
    request.body = JSON.parse(body);
    if (req.url === "/api/generate") {
      pendingLoad = res;
      return;
    }
    res.setHeader("Content-Type", "text/event-stream");
    res.end(
      `data: ${JSON.stringify({
        id: "ollama-test",
        model: name,
        choices: [
          {
            index: 0,
            delta: { content: "LOCAL_READY" },
            finish_reason: "stop",
          },
        ],
      })}\n\ndata: [DONE]\n\n`,
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanups.push(
    () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  );
  const catalog: OllamaCatalog = {
    baseURL: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    models: [
      {
        id: name,
        running: stale,
        contextLength: 4_096,
        maxOutputTokens: 1_024,
      },
    ],
  };
  const bus = new AgentEventBus();
  const events: AgentEventMap["model-loading"][] = [];
  const toolNames: string[] = [];
  bus.on("model-loading", (e) => events.push(e));
  bus.on("tool-call-start", (e) => toolNames.push(e.toolName));
  bus.on("error", () => {});
  const controller = new AbortController();
  const rootPath = mkdtempSync(join(tmpdir(), "apex-ollama-loading-"));
  cleanups.push(() => rmSync(rootPath, { recursive: true, force: true }));
  const agent = new OffensiveSecurityAgent({
    prompt: "Say LOCAL_READY",
    messages: [{ role: "user", content: "Say LOCAL_READY" }],
    // Fits the loaded context but cannot fit the cold catalog's 4K budget.
    system: "Follow the user's instructions. ".repeat(psSupported ? 500 : 1),
    model,
    activeTools: [],
    authConfig: { ollama: catalog },
    eventBus: bus,
    abortSignal: controller.signal,
    session: {
      id: "ses_ollama_loading",
      version: "1.0.0",
      targets: [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath,
      logsPath: join(rootPath, "logs"),
      findingsPath: join(rootPath, "findings"),
      scratchpadPath: join(rootPath, "scratchpad"),
      pocsPath: join(rootPath, "pocs"),
      config: {},
    } as SessionInfo,
  });
  return {
    agent,
    events,
    toolNames,
    requests,
    catalog,
    controller,
    async waitForLoad() {
      await vi.waitFor(() => expect(pendingLoad).toBeDefined());
    },
    finishLoad(error?: string) {
      if (!pendingLoad) throw new Error("No pending model load");
      loaded = !error;
      pendingLoad.statusCode = error ? 503 : 200;
      pendingLoad.end(
        JSON.stringify(error ? { error } : { done: true, done_reason: "load" }),
      );
    },
  };
}

describe("Ollama agent loading lifecycle", () => {
  it.each([
    false,
    true,
  ])("loads before fitting, even with stale running=%s metadata", async (stale) => {
    const f = await fixture({ stale });
    expect(() => f.agent.streamResult).toThrow("Await streamReady()");
    const run = f.agent.consume();
    await f.waitForLoad();
    expect(f.events).toEqual([
      expect.objectContaining({
        model,
        status: "loading",
        sessionId: "ses_ollama_loading",
      }),
    ]);
    expect(f.requests.map((r) => r.url)).toEqual(["/api/ps", "/api/generate"]);
    expect(f.requests[1].body).toEqual({ model: name, stream: false });
    expect(f.toolNames).not.toContain("summarize_conversation");
    expect(f.agent.streamReady()).toBe(f.agent.streamReady());
    f.finishLoad();
    await run;
    expect(f.events.map((e) => e.status)).toEqual(["loading", "ready"]);
    expect(f.events[1].elapsedMs).toBeGreaterThanOrEqual(0);
    expect(f.requests.map((r) => r.url)).toEqual([
      "/api/ps",
      "/api/generate",
      "/api/ps",
      "/v1/chat/completions",
    ]);
    expect(f.requests[3].body).toMatchObject({
      model: name,
      max_tokens: 4_096,
    });
    expect(await f.agent.streamResult.text).toBe("LOCAL_READY");
    expect(f.toolNames).not.toContain("summarize_conversation");
    expect(f.catalog.models[0].contextLength).toBe(4_096);
  });

  it("refreshes a warm model's context without loading again or showing a loading state", async () => {
    const f = await fixture({ warm: true });
    await f.agent.consume();
    expect(f.events).toEqual([]);
    expect(f.requests.map((r) => r.url)).toEqual([
      "/api/ps",
      "/v1/chat/completions",
    ]);
    expect(f.requests[1].body?.max_tokens).toBe(4_096);
    expect(f.toolNames).not.toContain("summarize_conversation");
  });

  it("ends the loading state and never infers after a load failure", async () => {
    const f = await fixture();
    const run = f.agent.consume();
    const rejected = expect(run).rejects.toThrow("insufficient memory");
    await f.waitForLoad();
    f.finishLoad("insufficient memory");
    await rejected;
    expect(f.events.map((e) => e.status)).toEqual(["loading", "failed"]);
    expect(f.requests.map((r) => r.url)).toEqual(["/api/ps", "/api/generate"]);
  });

  it("cancels a pending weight load without starting inference", async () => {
    const f = await fixture();
    const run = f.agent.consume();
    const rejected = expect(run).rejects.toMatchObject({ name: "AbortError" });
    await f.waitForLoad();
    f.controller.abort();
    await rejected;
    f.finishLoad();
    expect(f.events.map((e) => e.status)).toEqual(["loading", "cancelled"]);
    expect(f.requests.map((r) => r.url)).toEqual(["/api/ps", "/api/generate"]);
  });

  it("does not contact Ollama when already cancelled", async () => {
    const f = await fixture();
    f.controller.abort();
    await expect(f.agent.consume()).rejects.toMatchObject({
      name: "AbortError",
    });
    expect(f.events).toEqual([]);
    expect(f.requests).toEqual([]);
  });

  it("supports servers without running-model metadata using the conservative budget", async () => {
    const f = await fixture({ psSupported: false });
    const run = f.agent.consume();
    await f.waitForLoad();
    f.finishLoad();
    await run;
    expect(f.events.map((e) => e.status)).toEqual(["loading", "ready"]);
    expect(f.requests.at(-1)?.body?.max_tokens).toBe(1_024);
  });
});
