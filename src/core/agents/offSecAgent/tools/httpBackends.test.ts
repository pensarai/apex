import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocalBackends } from "../../../tools/backends/local";
import { getPage } from "./getPage";
import { httpRequest } from "./httpRequest";
import type { ToolContext } from "./types";

const options = { toolCallId: "test", messages: [] };
const roots: string[] = [];
function context(): ToolContext {
  const root = mkdtempSync(join(tmpdir(), "http-backends-"));
  roots.push(root);
  return {
    agentCwd: root,
    target: "https://example.com",
    session: {
      id: "test",
      rootPath: root,
      logsPath: root,
      targets: ["https://example.com"],
    },
  } as ToolContext;
}
const response = {
  success: true,
  status: 401,
  statusText: "Unauthorized",
  headers: {},
  body: "credential required",
  url: "https://example.com/",
  redirected: false,
};
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe("injected HTTP backends", () => {
  it("keeps default sandbox HTTP execution remote with bounded capture", async () => {
    const ctx = context();
    const hostFetch = vi.fn();
    vi.stubGlobal("fetch", hostFetch);
    const execute = vi.fn(async (command: string) => {
      const nonce = command.match(/__APEX_([0-9a-f]+)_CURL_EXIT_/)?.[1];
      return {
        success: true,
        exitCode: 0,
        stdout: Buffer.from(
          `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nremote body\n__APEX_${nonce}_CURL_EXIT_0\n`,
        ).toString("base64"),
        stderr: "",
      };
    });
    ctx.sandbox = { execute } as unknown as NonNullable<ToolContext["sandbox"]>;
    const result = await LocalBackends(ctx).http.request(
      { url: response.url },
      { timeoutMs: 5000 },
    );
    expect(result).toMatchObject({
      success: true,
      body: "remote body",
      capture: { complete: true },
    });
    expect(execute.mock.calls[0][0]).toContain("head -c");
    expect(execute.mock.calls[0][0]).toContain("--max-time 5");
    expect(hostFetch).not.toHaveBeenCalled();
  });

  it("uses the supplied backend exclusively and retains completed authentication responses", async () => {
    const ctx = context();
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const backends = LocalBackends(ctx);
    const request = vi
      .spyOn(backends.http, "request")
      .mockResolvedValue(response);
    ctx.backends = backends;
    const result = await httpRequest(ctx).execute!(
      {
        url: response.url,
        method: "GET",
        followRedirects: false,
        timeout: 2345,
        toolCallDescription: "test",
      },
      options,
    );
    expect(result).toMatchObject(response);
    expect(request).toHaveBeenCalledWith(
      {
        url: response.url,
        method: "GET",
        headers: {},
        body: undefined,
        followRedirects: false,
      },
      { timeoutMs: 2345, abortSignal: undefined },
    );
    expect(fetch).not.toHaveBeenCalled();
    request.mockRejectedValue(new Error("executor unavailable"));
    await expect(
      httpRequest(ctx).execute!(
        {
          url: response.url,
          method: "GET",
          followRedirects: false,
          timeout: 2345,
          toolCallDescription: "test",
        },
        options,
      ),
    ).rejects.toThrow("executor unavailable");
    expect(fetch).not.toHaveBeenCalled();
  });
  it("retains partial readability content and the producer stop reason", async () => {
    const ctx = context();
    ctx.backends = LocalBackends(ctx);
    vi.spyOn(ctx.backends.http, "request").mockResolvedValue({
      ...response,
      success: false,
      body: "partial content",
      error: "timeout",
      contentTruncated: true,
      stopReason: "timeout",
    });
    expect(
      await getPage(ctx).execute!(
        { url: response.url, toolCallDescription: "test" },
        options,
      ),
    ).toMatchObject({
      success: false,
      content: "partial content",
      error: "timeout",
      contentTruncated: true,
      stopReason: "timeout",
    });
  });
  it("keeps the deadline active after headers and preserves the captured prefix", async () => {
    vi.useFakeTimers();
    const cancel = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(new TextEncoder().encode("prefix"));
            },
            cancel,
          }),
          { status: 200 },
        ),
      ),
    );
    const promise = LocalBackends(context()).http.request(
      { url: response.url },
      { timeoutMs: 25 },
    );
    await vi.advanceTimersByTimeAsync(30);
    const result = await promise;
    expect(result).toMatchObject({
      success: false,
      body: "prefix",
      capture: { complete: false, stopReason: "timeout", capturedBytes: 6 },
    });
    expect(cancel).toHaveBeenCalled();
  });
  it("caps readability capture before extracting partial content", async () => {
    const cancel = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(
                new TextEncoder().encode("a".repeat(5 * 1024 * 1024 + 1)),
              );
            },
            cancel,
          }),
          { headers: { "content-type": "text/plain" } },
        ),
      ),
    );
    const result = await LocalBackends(context()).http.request({
      url: response.url,
      extract: "readability",
    });
    expect(result).toMatchObject({
      success: false,
      contentTruncated: true,
      stopReason: "byte-cap",
    });
    expect(result.body.length).toBeLessThan(51000);
    expect(result.body).toContain("INCOMPLETE");
    expect(cancel).toHaveBeenCalled();
  });
});
