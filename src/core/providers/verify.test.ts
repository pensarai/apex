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
