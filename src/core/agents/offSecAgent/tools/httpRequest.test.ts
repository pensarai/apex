import { afterEach, describe, expect, it, vi } from "vitest";
import {
  promptInjectionRef,
  StaticPromptInjectionLibrary,
} from "../../../prompt-injections";
import { RateLimiter } from "../../../services/rateLimiter";
import type { SessionInfo } from "../../../session";
import { type HttpRequestResult, httpRequest } from "./httpRequest";
import type { ToolContext } from "./types";

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
    expect(acquireSlot).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("acquires one slot before the sandbox curl dispatch", async () => {
    const { ctx, acquireSlot } = ctxWithLimiter();
    const execute = vi.fn(async () => ({
      success: true,
      exitCode: 0,
      stdout: "HTTP/1.1 200 OK\n\n",
      stderr: "",
    }));
    ctx.sandbox = { execute } as unknown as ToolContext["sandbox"];

    const result = (await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/api",
        method: "GET",
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Sandbox GET",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(acquireSlot).toHaveBeenCalledTimes(1);
    expect(execute).toHaveBeenCalledTimes(1);
    expect(result.status).toBe(200);
  });

  it("deletes the request-body temp file after a sandbox POST", async () => {
    const { ctx } = ctxWithLimiter();
    const commands: string[] = [];
    const execute = vi.fn(async (command: string) => {
      commands.push(command);
      return {
        success: true,
        exitCode: 0,
        stdout: "HTTP/1.1 200 OK\n\n",
        stderr: "",
      };
    });
    ctx.sandbox = { execute } as unknown as ToolContext["sandbox"];

    await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/api",
        method: "POST",
        body: "hello=world",
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Sandbox POST",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    );

    const bodyFile = commands
      .join("\n")
      .match(/\/tmp\/apex_http_body_[^\s"']+\.txt/)?.[0];
    expect(bodyFile).toBeDefined();
    // The temp file is both written (curl --data-binary) and removed.
    expect(commands.some((c) => c.includes(`rm -f ${bodyFile}`))).toBe(true);
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
