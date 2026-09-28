import { afterEach, describe, expect, it, vi } from "vitest";
import { loadHoonifyModels } from "./hoonify";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

describe("Hoonify catalog", () => {
  it("accepts the live OpenAI model-list shape without context metadata", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          object: "list",
          data: [
            {
              id: "partner-model",
              object: "model",
              created: 1,
              owned_by: "hoonify",
            },
          ],
        }),
      ),
    );
    await expect(
      loadHoonifyModels("standard-catalog-key", true),
    ).resolves.toEqual([
      { id: "partner-model", contextLength: 32_768, maxOutputTokens: 4096 },
    ]);
  });

  it("uses bearer auth and catalog context windows without guessing model aliases", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({
        data: [
          { id: "Qwen/Qwen3.6-27B", context_window: 262_144, owned_by: "Qwen" },
          { id: "small", context_window: 8192 },
        ],
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const models = await loadHoonifyModels("  catalog-auth-key\n", true);
    expect(fetchMock).toHaveBeenCalledWith("https://api.hoonify.ai/v1/models", {
      headers: { Authorization: "Bearer catalog-auth-key" },
      signal: expect.any(AbortSignal),
    });
    expect(models).toEqual([
      { id: "Qwen/Qwen3.6-27B", contextLength: 262_144, maxOutputTokens: 4096 },
      { id: "small", contextLength: 8192, maxOutputTokens: 2048 },
    ]);
  });

  it.each([
    { context_window: undefined, expected: 1_000_000 },
    { context_window: 131_072, expected: 131_072 },
  ])("uses the published GLM-5.2 limit only when the API omits it: $context_window", async ({
    context_window,
    expected,
  }) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({ data: [{ id: "zai-org/GLM-5.2", context_window }] }),
      ),
    );
    expect(await loadHoonifyModels("published-context-key", true)).toEqual([
      {
        id: "zai-org/GLM-5.2",
        contextLength: expected,
        maxOutputTokens: 4096,
      },
    ]);
  });

  it("applies per-model context overrides without changing the cached catalog", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({
        data: [
          { id: "zai-org/GLM-5.2" },
          { id: "other", context_window: 262_144 },
        ],
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const original = await loadHoonifyModels("context-override-key", true);
    vi.stubEnv(
      "HOONIFY_CONTEXT_WINDOWS",
      JSON.stringify({ "zai-org/GLM-5.2": 131_072 }),
    );
    expect(await loadHoonifyModels("context-override-key")).toEqual([
      { id: "zai-org/GLM-5.2", contextLength: 131_072, maxOutputTokens: 4096 },
      { id: "other", contextLength: 262_144, maxOutputTokens: 4096 },
    ]);
    vi.stubEnv("HOONIFY_CONTEXT_WINDOWS", "  ");
    expect(await loadHoonifyModels("context-override-key")).toEqual(original);
    expect(original[0].contextLength).toBe(1_000_000);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("can lower a reported window without exceeding the output budget", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({ data: [{ id: "model", context_window: 131_072 }] }),
      ),
    );
    vi.stubEnv("HOONIFY_CONTEXT_WINDOWS", '{"model":8192}');
    expect(await loadHoonifyModels("lower-context-key", true)).toEqual([
      { id: "model", contextLength: 8192, maxOutputTokens: 2048 },
    ]);
  });

  it.each([
    "invalid-json",
    "null",
    "[]",
    '{"model":"131072"}',
    '{"model":0}',
    '{"model":1.5}',
    '{"model":9007199254740992}',
  ])("rejects invalid context overrides before loading models: %s", async (value) => {
    vi.stubEnv("HOONIFY_CONTEXT_WINDOWS", value);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      loadHoonifyModels("invalid-override-key", true),
    ).rejects.toThrow(
      "HOONIFY_CONTEXT_WINDOWS must be a JSON object mapping exact model IDs to integer context windows",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("coalesces loads, expires the cache, and isolates credentials", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn(async () =>
      Response.json({
        data: [
          {
            id: `model-${fetchMock.mock.calls.length}`,
            context_window: 32_768,
          },
        ],
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const [first, concurrent] = await Promise.all([
      loadHoonifyModels("cache-key-a", true),
      loadHoonifyModels("cache-key-a"),
    ]);
    expect(first).toEqual(concurrent);
    expect(await loadHoonifyModels("cache-key-a")).toEqual(first);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(5 * 60_000);
    expect(await loadHoonifyModels("cache-key-a")).not.toEqual(first);
    expect(await loadHoonifyModels("cache-key-b")).not.toEqual(first);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it.each([
    401, 403, 429, 503,
  ])("surfaces HTTP %s without exposing response bodies", async (status) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("secret-body", { status })),
    );
    const request = loadHoonifyModels(`http-${status}`, true);
    await expect(request).rejects.toThrow(
      status === 401 || status === 403
        ? "rejected the API key"
        : `HTTP ${status}`,
    );
    await expect(request).rejects.not.toThrow("secret-body");
  });

  it.each([
    {},
    { data: [{ object: "model" }] },
    { data: [{ id: " " }] },
    { data: [{ id: "test", context_window: 0 }] },
    { data: [{ id: "test", context_window: null }] },
    { data: [{ id: "test", context_window: "32768" }] },
    { data: [] },
    {
      data: [
        { id: "test", context_window: 32_768 },
        { id: "test", context_window: 32_768 },
      ],
    },
  ])("rejects unusable catalogs", async (body) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json(body)),
    );
    await expect(loadHoonifyModels("invalid-catalog", true)).rejects.toThrow(
      /Hoonify/,
    );
  });

  it("retries a failed load instead of caching the failure", async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error("secret network details"))
      .mockResolvedValueOnce(
        Response.json({ data: [{ id: "recovered", context_window: 32_768 }] }),
      );
    vi.stubGlobal("fetch", fetchMock);
    await expect(loadHoonifyModels("retry-key", true)).rejects.toThrow(
      "Check connectivity",
    );
    expect((await loadHoonifyModels("retry-key"))[0].id).toBe("recovered");
  });

  it("identifies catalog schema failures without exposing response values", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          data: [{ id: "private-model", context_window: "private-value" }],
          private_field: "private-body",
        }),
      ),
    );
    const result = loadHoonifyModels("private-key", true);
    await expect(result).rejects.toThrow(
      "Missing or invalid fields: data.0.context_window",
    );
    await expect(result).rejects.not.toThrow("private-");
  });
});
