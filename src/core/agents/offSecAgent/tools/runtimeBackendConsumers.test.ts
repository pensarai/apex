import { afterEach, describe, expect, it, vi } from "vitest";
import { LocalBackends } from "../../../tools/backends/local";
import type { SubagentSpawner } from "../subagentSpawner";
import { spawnCodingAgent } from "./spawnCodingAgent";
import { testEndpointVariations } from "./testEndpointVariations";
import { generateThreatModelForEndpoint } from "./threatModelGenerator";
import type { ToolContext } from "./types";

const options = { toolCallId: "parent-call", messages: [] };
function context(): ToolContext {
  const ctx = {
    agentCwd: "/workspace",
    model: "test-model",
    target: "https://example.com",
    session: {
      id: "test",
      rootPath: "/workspace",
      targets: ["https://example.com"],
    },
  } as ToolContext;
  ctx.backends = LocalBackends(ctx);
  return ctx;
}
afterEach(() => vi.unstubAllGlobals());

describe("remaining runtime backend consumers", () => {
  it.each([
    401, 403, 500, 200, 0,
  ])("classifies status %s independently of body capture success", async (status) => {
    const ctx = context();
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const request = vi.spyOn(ctx.backends!.http, "request").mockResolvedValue({
      success: false,
      status,
      statusText: "Unauthorized",
      headers: {},
      body: "sign in",
      url: ctx.target!,
      redirected: false,
      error:
        status === 0
          ? "connection failed"
          : status === 200
            ? "body capped"
            : undefined,
      capture: {
        complete: status !== 200,
        stopReason: status === 200 ? "byte-cap" : "end",
        capturedBytes: 7,
        capturedBytesBasis: "raw",
      },
    });
    const result = await testEndpointVariations(ctx).execute!(
      {
        endpoints: [ctx.target!],
        sessionCookie: "session=test",
        toolCallDescription: "test",
      },
      options,
    );
    expect(result).toMatchObject({
      results: [
        status === 0
          ? { status: 0, accessible: false, error: "connection failed" }
          : {
              endpoint: ctx.target,
              status,
              accessible: status === 200,
              contentLength: 7,
            },
      ],
    });
    if ("results" in result && result.results && status !== 0)
      expect(result.results[0]).not.toHaveProperty("error");
    expect(request).toHaveBeenCalledWith({
      url: ctx.target,
      method: "GET",
      followRedirects: true,
      headers: { Cookie: "session=test" },
    });
    expect(fetch).not.toHaveBeenCalled();
    request.mockRejectedValue(new Error("executor unavailable"));
    expect(
      await testEndpointVariations(ctx).execute!(
        { endpoints: [ctx.target!], toolCallDescription: "test" },
        options,
      ),
    ).toMatchObject({
      results: [{ status: 0, error: "executor unavailable" }],
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("forwards the execution backend to coding children", async () => {
    const ctx = context();
    const spawn = vi.fn().mockResolvedValue({ text: "done" });
    ctx.subagentSpawner = {
      spawn,
      spawnMany: async <T, R>(
        items: readonly T[],
        fn: (item: T, index: number) => Promise<R>,
      ) => Promise.all(items.map(fn)),
    } as unknown as SubagentSpawner;
    expect(
      await spawnCodingAgent(ctx).execute!(
        {
          tasks: [
            {
              name: "review",
              codebasePath: "/workspace",
              objective: "review files",
            },
          ],
          toolCallDescription: "test",
        },
        options,
      ),
    ).toMatchObject({ success: true, results: [{ output: "done" }] });
    expect(spawn.mock.calls[0][0].runtime.backends).toBe(ctx.backends);
  });

  it("forwards the execution backend to endpoint analysis children", async () => {
    const ctx = context();
    const spawn = vi.fn().mockResolvedValue(undefined);
    ctx.subagentSpawner = { spawn } as unknown as SubagentSpawner;
    await generateThreatModelForEndpoint(ctx, {
      appName: "Example",
      routePath: "/items",
      description: "Reads items",
    });
    expect(spawn).toHaveBeenCalledOnce();
    expect(spawn.mock.calls[0][0].runtime.backends).toBe(ctx.backends);
  });
});
