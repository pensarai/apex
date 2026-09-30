import { createServer } from "node:http";
import { afterEach, expect, it, vi } from "vitest";
import { fetchOpenAIPro } from "./openai-pro-fetch";

afterEach(() => vi.unstubAllGlobals());

it("extends Bun's HTTP idle window and preserves caller cancellation", async () => {
  vi.stubGlobal("Bun", {});
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      Response.json({ ok: true }),
  );
  vi.stubGlobal("fetch", fetchMock);
  const controller = new AbortController();
  await fetchOpenAIPro("https://api.openai.com/v1/responses", {
    signal: controller.signal,
  });
  const options = fetchMock.mock.calls[0]?.[1];
  expect(options).toMatchObject({ timeout: false });
  expect(options?.signal?.aborted).toBe(false);
  controller.abort();
  expect(options?.signal?.aborted).toBe(true);
});

it("returns a real Node HTTP response with its headers and JSON body", async () => {
  const server = createServer((_request, response) => {
    response.writeHead(200, {
      "content-type": "application/json",
      "x-test": "ok",
    });
    response.end('{"ok":true}');
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("No server port");
    const response = await fetchOpenAIPro(`http://127.0.0.1:${address.port}`);
    expect(response.headers.get("x-test")).toBe("ok");
    expect(await response.json()).toEqual({ ok: true });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

it("aborts a Node request while it is waiting for response headers", async () => {
  const controller = new AbortController();
  const server = createServer(() => controller.abort());
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("No server port");
    await expect(
      fetchOpenAIPro(`http://127.0.0.1:${address.port}`, {
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ name: "AbortError" });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
