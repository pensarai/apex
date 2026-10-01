import { afterEach, describe, expect, it, vi } from "vitest";
import {
  promptInjectionRef,
  StaticPromptInjectionLibrary,
} from "../../../prompt-injections";
import { RateLimiter } from "../../../services/rateLimiter";
import type { SessionInfo } from "../../../session";
import type {
  HttpOpts,
  HttpRequest,
  ToolBackends,
} from "../../../tools/backends/types";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { type HttpRequestResult, httpRequest } from "./httpRequest";
import type { ToolContext } from "./types";

// The host branch resolves hostnames before fetching; keep unit tests offline.
vi.mock("node:dns/promises", () => ({
  lookup: vi.fn(async () => [{ address: "93.184.216.34", family: 4 }]),
}));

const TEST_LIBRARY = new StaticPromptInjectionLibrary([
  {
    id: "pi.direct.override",
    name: "Direct Override",
    category: "instruction-hijack",
    description: "Safe metadata for a direct override test.",
    tags: ["baseline"],
    deliveryHints: ["json-body"],
    expectedObservation: "The system should preserve hierarchy.",
    payload: "TEST PAYLOAD: direct override",
  },
]);

function makeCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: ["https://example.com"],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/test",
      logsPath: "/tmp/test/logs",
      findingsPath: "/tmp/test/findings",
      scratchpadPath: "/tmp/test/scratchpad",
      pocsPath: "/tmp/test/pocs",
    } as SessionInfo,
    agentCwd: "/tmp/test",
    target: "https://example.com",
    ...overrides,
  };
}

describe("httpRequest prompt injection refs", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("resolves body refs only at execution time and redacts echoed payloads", async () => {
    const id = "pi.direct.override";
    const payload = TEST_LIBRARY.getPayload(id)!;
    let capturedBody: BodyInit | null | undefined;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init?: RequestInit) => {
        capturedBody = init?.body;
        return new Response(`server echoed ${String(init?.body)}`, {
          status: 200,
          headers: { "x-echo": String(init?.body) },
        });
      }),
    );

    const tool = httpRequest(makeCtx({ promptInjectionLibrary: TEST_LIBRARY }));
    const result = (await tool.execute?.(
      {
        url: "https://example.com/chat",
        method: "POST",
        body: promptInjectionRef(id),
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Send hidden prompt-injection reference",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(capturedBody).toBe(payload);
    expect(result.success).toBe(true);
    expect(result.body).toContain(`[PROMPT_INJECTION:${id}]`);
    expect(result.body).not.toContain(payload);
    expect(result.headers["x-echo"]).toBe(`[PROMPT_INJECTION:${id}]`);
  });

  it("does not resolve inline placeholder strings in request bodies", async () => {
    let capturedBody: BodyInit | null | undefined;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init?: RequestInit) => {
        capturedBody = init?.body;
        return new Response("ok", { status: 200 });
      }),
    );

    const tool = httpRequest(makeCtx({ promptInjectionLibrary: TEST_LIBRARY }));
    await tool.execute?.(
      {
        url: "https://example.com/chat",
        method: "POST",
        body: "payload={{prompt_injection:pi.encoded.override}}",
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Send literal placeholder text",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    );

    expect(capturedBody).toBe(
      "payload={{prompt_injection:pi.encoded.override}}",
    );
  });
});

describe("httpRequest rate limiting", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  function ctxWithLimiter() {
    const limiter = new RateLimiter({ requestsPerSecond: 5 });
    const acquireSlot = vi
      .spyOn(limiter, "acquireSlot")
      .mockResolvedValue(true);
    const ctx = makeCtx();
    ctx.session._rateLimiter = limiter;
    return { ctx, acquireSlot };
  }

  it("acquires exactly one rate-limit slot per dispatched request", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("ok", { status: 200 })),
    );
    const { ctx, acquireSlot } = ctxWithLimiter();

    await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/api",
        method: "GET",
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Rate-limited GET",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    );

    expect(acquireSlot).toHaveBeenCalledTimes(1);
  });

  it("does not consume a slot when the request is out of scope", async () => {
    const fetchSpy = vi.fn(async () => new Response("ok", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    const { ctx, acquireSlot } = ctxWithLimiter();

    const result = (await httpRequest(ctx).execute?.(
      {
        url: "https://evil.com/",
        method: "GET",
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Out-of-scope GET",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Scope violation/);
    expect(acquireSlot).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("returns an aborted result without dispatching when already aborted", async () => {
    const fetchSpy = vi.fn(async () => new Response("ok", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    const { ctx } = ctxWithLimiter();
    const controller = new AbortController();
    controller.abort();
    ctx.abortSignal = controller.signal;

    const result = (await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/api",
        method: "GET",
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Aborted GET",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: controller.signal },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("aborted");
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
describe("httpRequest routes through the injected HTTP backend", () => {
  function fakeBackends(
    respond: (
      req: HttpRequest,
      opts?: HttpOpts,
    ) => ReturnType<ToolBackends["http"]["request"]>,
  ): { backends: ToolBackends; calls: HttpRequest[] } {
    const calls: HttpRequest[] = [];
    const backends = {
      http: {
        request: async (req: HttpRequest, opts?: HttpOpts) => {
          calls.push(req);
          return respond(req, opts);
        },
      },
    } as unknown as ToolBackends;
    return { backends, calls };
  }

  it("calls backends.http.request with the resolved request, no host fetch/curl reference", async () => {
    const { backends, calls } = fakeBackends(async () => ({
      success: true,
      status: 200,
      statusText: "OK",
      headers: { "x-test": "1" },
      body: "hi",
      url: "https://example.com/api",
      redirected: false,
    }));

    const result = (await httpRequest(makeCtx({ backends })).execute?.(
      {
        url: "https://example.com/api",
        method: "GET",
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "d",
      },
      { toolCallId: "tc", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      url: "https://example.com/api",
      method: "GET",
    });
    expect(result.status).toBe(200);
    expect(result.body).toBe("hi");
  });

  it("routes extract: 'readability' through the backend and skips the rate limiter", async () => {
    const { backends, calls } = fakeBackends(async () => ({
      success: true,
      status: 200,
      statusText: "OK",
      headers: {},
      body: "extracted text",
      title: "A Page",
      url: "https://example.com/advisory",
      redirected: false,
    }));
    const limiter = new RateLimiter({ requestsPerSecond: 5 });
    const acquireSlot = vi.spyOn(limiter, "acquireSlot");
    const ctx = makeCtx({ backends });
    ctx.session._rateLimiter = limiter;

    const result = (await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/advisory",
        method: "GET",
        followRedirects: false,
        timeout: 1000,
        extract: "readability",
        toolCallDescription: "d",
      },
      { toolCallId: "tc", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(calls).toEqual([
      { url: "https://example.com/advisory", extract: "readability" },
    ]);
    expect(acquireSlot).not.toHaveBeenCalled();
    expect(result.success).toBe(true);
    expect(result.body).toBe("extracted text");
    expect(result.title).toBe("A Page");
  });
});
