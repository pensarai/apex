import { describe, expect, it } from "vitest";
import {
  createLocalResearchFetchToken,
  verifyLocalResearchFetchToken,
} from "./researchFetchToken";

describe("local research fetch tokens", () => {
  it("binds a short-lived capability to one normalized URL", () => {
    const now = Date.parse("2026-10-15T00:00:00.000Z");
    const token = createLocalResearchFetchToken(
      "https://docs.example/path",
      now,
    );

    expect(
      verifyLocalResearchFetchToken(
        token,
        "https://docs.example/path",
        now + 1,
      ),
    ).toBe(true);
    expect(
      verifyLocalResearchFetchToken(
        token,
        "https://docs.example/other",
        now + 1,
      ),
    ).toBe(false);
    expect(
      verifyLocalResearchFetchToken(
        token,
        "https://docs.example/path",
        now + 11 * 60 * 1000,
      ),
    ).toBe(false);
  });

  it("rejects tampering and non-HTTP destinations", () => {
    const token = createLocalResearchFetchToken("https://docs.example/");
    expect(
      verifyLocalResearchFetchToken(
        `${token.slice(0, -1)}x`,
        "https://docs.example/",
      ),
    ).toBe(false);
    expect(() => createLocalResearchFetchToken("file:///etc/passwd")).toThrow(
      /protocol/i,
    );
  });
});
