import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { z } from "zod";
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

  it("re-resolves sandbox curl headers for every redirect destination", async () => {
    const ctx = context();
    ctx.session.config = {
      headers: { "X-Session-Secret": "session-secret" },
    } as NonNullable<ToolContext["session"]["config"]>;
    ctx.session.credentialManager = {
      listCredentialsWithHeaders: () => [
        {
          tokens: {
            customHeaders: {
              "X-Credential-Secret": "credential-secret",
            },
          },
        },
      ],
    } as unknown as ToolContext["session"]["credentialManager"];
    const commands: string[] = [];
    const execute = vi.fn(async (command: string) => {
      commands.push(command);
      const nonce = command.match(/__APEX_([0-9a-f]+)_CURL_EXIT_/)?.[1];
      const wire =
        commands.length === 1
          ? "HTTP/1.1 302 Found\r\nLocation: https://outside.example.net/final\r\nContent-Length: 0\r\n\r\n"
          : "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nsafe";
      return {
        success: true,
        exitCode: 0,
        stdout: Buffer.from(`${wire}\n__APEX_${nonce}_CURL_EXIT_0\n`).toString(
          "base64",
        ),
        stderr: "",
      };
    });
    ctx.sandbox = {
      type: "linux",
      execute,
    } as unknown as NonNullable<ToolContext["sandbox"]>;

    const result = await LocalBackends(ctx).http.request(
      {
        url: "https://example.com/start",
        followRedirects: true,
      },
      { timeoutMs: 5000 },
    );

    expect(execute).toHaveBeenCalledTimes(2);
    expect(commands[0]).toContain("X-Session-Secret: session-secret");
    expect(commands[0]).toContain("X-Credential-Secret: credential-secret");
    expect(commands[1]).not.toContain("X-Session-Secret");
    expect(commands[1]).not.toContain("X-Credential-Secret");
    expect(commands.join("\n")).not.toMatch(/\scurl\b[^\n]*\s-L(?:\s|$)/);
    expect(result).toMatchObject({
      success: true,
      url: "https://outside.example.net/final",
      redirected: true,
      redirectChain: [
        "https://example.com/start",
        "https://outside.example.net/final",
      ],
    });
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

describe("redirect credential isolation", () => {
  const servers: Server[] = [];

  afterEach(async () => {
    await Promise.all(
      servers
        .splice(0)
        .map(
          (server) =>
            new Promise<void>((resolve) => server.close(() => resolve())),
        ),
    );
  });

  async function listen(server: Server): Promise<number> {
    servers.push(server);
    server.listen(0);
    await once(server, "listening");
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("test server did not bind");
    }
    return address.port;
  }

  it("keeps get_page and local http_request credentials on the target host", async () => {
    const received = new Map<string, import("node:http").IncomingHttpHeaders>();
    const outsidePort = await listen(
      createServer((request, response) => {
        received.set(request.url ?? "/", request.headers);
        response.writeHead(200, { "Content-Type": "text/html" });
        response.end("<html><head><title>Outside</title></head></html>");
      }),
    );
    const targetPort = await listen(
      createServer((request, response) => {
        const destination =
          request.url === "/page" ? "/page-final" : "/http-final";
        response.writeHead(302, {
          Location: `http://127.0.0.1:${outsidePort}${destination}`,
        });
        response.end();
      }),
    );
    const target = `http://localhost:${targetPort}`;
    const ctx = context();
    ctx.target = target;
    ctx.session.targets = [target];
    ctx.session.config = {
      headers: { "X-Session-Secret": "session-secret" },
    } as NonNullable<ToolContext["session"]["config"]>;
    ctx.session.credentialManager = {
      listCredentialsWithHeaders: () => [
        {
          tokens: {
            customHeaders: {
              "X-Credential-Secret": "credential-secret",
            },
          },
        },
      ],
    } as unknown as ToolContext["session"]["credentialManager"];

    const pageResult = await getPage(ctx).execute!(
      {
        url: `${target}/page`,
        toolCallDescription: "test redirect scoping",
      },
      options,
    );
    const httpResult = await httpRequest(ctx).execute!(
      {
        url: `${target}/http`,
        method: "GET",
        followRedirects: true,
        timeoutMs: 5000,
        toolCallDescription: "test redirect scoping",
      },
      options,
    );

    for (const path of ["/page-final", "/http-final"]) {
      expect(received.get(path)?.["x-session-secret"]).toBeUndefined();
      expect(received.get(path)?.["x-credential-secret"]).toBeUndefined();
    }
    expect(pageResult).toMatchObject({
      success: true,
      url: `http://127.0.0.1:${outsidePort}/page-final`,
      redirectChain: [
        `${target}/page`,
        `http://127.0.0.1:${outsidePort}/page-final`,
      ],
    });
    expect(httpResult).toMatchObject({
      success: true,
      url: `http://127.0.0.1:${outsidePort}/http-final`,
      redirected: true,
      redirectChain: [
        `${target}/http`,
        `http://127.0.0.1:${outsidePort}/http-final`,
      ],
    });
  });
});

it("does not expose the backend-only readability mode through http_request", () => {
  const schema = httpRequest(context()).inputSchema as z.ZodType;
  const parsed = schema.parse({
    url: response.url,
    extract: "readability",
    toolCallDescription: "test",
  });
  expect(parsed).not.toHaveProperty("extract");
});

it("enforces HTTP scope even if an unvalidated caller supplies readability mode", async () => {
  const ctx = context();
  ctx.backends = LocalBackends(ctx);
  const request = vi
    .spyOn(ctx.backends.http, "request")
    .mockResolvedValue(response);
  const result = await httpRequest(ctx).execute!(
    {
      url: "https://outside.example.org/",
      method: "GET",
      followRedirects: false,
      timeout: 1000,
      extract: "readability",
      toolCallDescription: "test",
    } as never,
    options,
  );
  expect(result).toMatchObject({ success: false });
  expect(request).not.toHaveBeenCalled();
});

describe("classic sandbox get_page keeps the host research fetch", () => {
  it.each([
    "timeout",
    "aborted",
  ])("preserves %s and cancels the body mid-read", async (reason) => {
    vi.useFakeTimers();
    const cancel = vi.fn();
    const execute = vi.fn();
    const controller = new AbortController();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          new ReadableStream({
            start(stream) {
              stream.enqueue(
                new TextEncoder().encode("<p>partial research</p>"),
              );
            },
            cancel,
          }),
          { status: 200, headers: { "content-type": "text/html" } },
        ),
      ),
    );
    const ctx = { ...context(), sandbox: { type: "linux" as const, execute } };
    const pending = LocalBackends(ctx).http.request(
      { url: "https://example.com", extract: "readability" },
      { timeoutMs: 25, abortSignal: controller.signal },
    );
    await vi.advanceTimersByTimeAsync(0);
    if (reason === "aborted") controller.abort();
    else await vi.advanceTimersByTimeAsync(30);
    await expect(pending).resolves.toMatchObject({
      success: false,
      contentTruncated: true,
      stopReason: reason,
      body: expect.stringContaining("partial research"),
    });
    expect(cancel).toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });
});
