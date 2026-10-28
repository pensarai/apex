import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyApiKey } from "./verify";

afterEach(() => vi.unstubAllGlobals());

describe("verifyApiKey Hoonify catalog access", () => {
  it("accepts the live catalog without requiring context metadata or a key prefix", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          object: "list",
          data: [
            { id: "test", object: "model", created: 1, owned_by: "hoonify" },
          ],
        }),
      ),
    );
    await expect(verifyApiKey("hoonify", "any-issued-key")).resolves.toEqual({
      valid: true,
    });
  });

  it("returns a useful error when the key has no models", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ data: [] })),
    );
    await expect(verifyApiKey("hoonify", "empty-key")).resolves.toEqual({
      valid: false,
      error: "No Hoonify models are available to this API key.",
    });
  });
});

describe("verifyApiKey Concentrate key format", () => {
  it("accepts the documented key prefix", async () => {
    await expect(verifyApiKey("concentrate", "sk-cn-test")).resolves.toEqual({
      valid: true,
    });
  });

  it("rejects keys without the documented prefix", async () => {
    await expect(verifyApiKey("concentrate", "sk-test")).resolves.toEqual({
      valid: false,
      error: "Concentrate API keys start with sk-cn",
    });
  });
});

describe("verifyApiKey Inference.net", () => {
  it("validates the bearer key without making an inference request", async () => {
    const fetchMock = vi.fn(async () => Response.json({ data: [] }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(verifyApiKey("inference", " test-key ")).resolves.toEqual({
      valid: true,
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.inference.net/v1/models",
      expect.objectContaining({
        method: "GET",
        headers: { Authorization: "Bearer test-key" },
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it.each([401, 403, 429, 500])("reports HTTP %s", async (status) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(null, { status })),
    );
    await expect(verifyApiKey("inference", "test-key")).resolves.toEqual({
      valid: false,
      error:
        status === 401 || status === 403
          ? "Invalid API key"
          : `Inference.net returned HTTP ${status}`,
    });
  });

  it("rejects empty keys before making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(verifyApiKey("inference", " ")).resolves.toEqual({
      valid: false,
      error: "Enter an Inference.net API key",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    [new Error("network failure"), "Could not reach Inference.net API"],
    [new DOMException("aborted", "AbortError"), "Request timed out"],
  ])("reports transport failures", async (error, message) => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(error));
    await expect(verifyApiKey("inference", "test-key")).resolves.toEqual({
      valid: false,
      error: message,
    });
  });
});
