import { afterEach, describe, expect, it, vi } from "vitest";
import { discoverOllama } from "./ollama";

const twil = "hf.co/webAI-Official/TwIL-8B:TwIL-8B-Q4_K_M-balanced.gguf";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("Ollama discovery", () => {
  it.each([
    ["localhost", "http://localhost:11434"],
    ["localhost:80", "http://localhost"],
    ["0.0.0.0:11435", "http://127.0.0.1:11435"],
    ["[::]:11434", "http://[::1]:11434"],
    ["::1", "http://[::1]:11434"],
    ["https://localhost", "https://localhost"],
  ])("uses Ollama's connection defaults for %s", async (host, baseURL) => {
    vi.stubEnv("OLLAMA_HOST", host);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ models: [] })),
    );
    expect((await discoverOllama())?.baseURL).toBe(baseURL);
  });

  it("discovers exact local IDs, prioritizes running models, and uses allocated context", async () => {
    vi.stubEnv("OLLAMA_HOST", "");
    const fetchMock = vi.fn(async (url: string) =>
      Response.json({
        models: url.endsWith("/ps")
          ? [{ name: twil, context_length: 32_768 }]
          : [
              { name: "qwen:8b" },
              {
                name: twil,
                capabilities: ["completion"],
                details: { context_length: 131_072 },
              },
              { name: twil },
              { name: "embed:latest", capabilities: ["embedding"] },
              { name: "cloud:latest", remote_model: "cloud" },
            ],
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    expect(await discoverOllama()).toEqual({
      baseURL: "http://127.0.0.1:11434",
      models: [
        {
          id: twil,
          contextLength: 32_768,
          maxOutputTokens: 4_096,
          running: true,
        },
        {
          id: "qwen:8b",
          contextLength: 4_096,
          maxOutputTokens: 1_024,
          running: false,
        },
      ],
    });
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "http://127.0.0.1:11434/api/tags",
      "http://127.0.0.1:11434/api/ps",
    ]);
  });

  it("honors OLLAMA_HOST and refreshes after install, removal, and restart", async () => {
    vi.stubEnv("OLLAMA_HOST", "localhost:12345/");
    const fetchMock = vi.fn(async (_url: string) =>
      Response.json({ models: [] }),
    );
    vi.stubGlobal("fetch", fetchMock);
    expect((await discoverOllama())?.models).toEqual([]);
    fetchMock.mockImplementation(async () =>
      Response.json({ models: [{ name: twil }] }),
    );
    expect((await discoverOllama())?.models[0].id).toBe(twil);
    fetchMock.mockRejectedValue(new Error("Connection refused"));
    expect(await discoverOllama()).toBeUndefined();
    fetchMock.mockImplementation(async () => Response.json({ models: [] }));
    expect((await discoverOllama())?.models).toEqual([]);
    expect(fetchMock.mock.calls[0][0]).toBe("http://localhost:12345/api/tags");
  });

  it("keeps installed models when running-model metadata is unsupported", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        url.endsWith("/ps")
          ? new Response(null, { status: 404 })
          : Response.json({ models: [{ name: twil }] }),
      ),
    );
    expect((await discoverOllama())?.models[0]).toMatchObject({
      id: twil,
      contextLength: 4_096,
      running: false,
    });
  });

  it.each([
    () => new Response(null, { status: 503 }),
    () => new Response("not json"),
    () => Response.json({ models: [{ name: 42 }] }),
  ])("ignores an unavailable or invalid catalog", async (response) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => response()),
    );
    expect(await discoverOllama()).toBeUndefined();
  });

  it("bounds discovery and cancels requests on unmount", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_url, init: RequestInit) =>
          new Promise((_resolve, reject) => {
            init.signal?.addEventListener(
              "abort",
              () => reject(init.signal?.reason),
              { once: true },
            );
          }),
      ),
    );
    const start = Date.now();
    expect(await discoverOllama()).toBeUndefined();
    expect(Date.now() - start).toBeLessThan(2_000);
    const controller = new AbortController();
    const pending = discoverOllama(controller.signal);
    controller.abort();
    expect(await pending).toBeUndefined();
  });
});
