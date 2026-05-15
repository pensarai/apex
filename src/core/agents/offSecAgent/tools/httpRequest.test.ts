import { afterEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../session";
import {
  StaticPromptInjectionLibrary,
  promptInjectionRef,
} from "../../../prompt-injections";
import { httpRequest, type HttpRequestResult } from "./httpRequest";
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
    const result = (await tool.execute!(
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
    await tool.execute!(
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

    expect(capturedBody).toBe("payload={{prompt_injection:pi.encoded.override}}");
  });
});
