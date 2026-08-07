import { describe, expect, it } from "vitest";
import { verifyApiKey } from "./verify";

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
