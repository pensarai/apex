import { describe, expect, it } from "vitest";
import type { ToolContext } from "../agents/offSecAgent/tools";
import { filterHarByScope } from "./scope";
import type { HarEntry } from "./types";

function entry(url: string): HarEntry {
  return {
    _id: url,
    startedDateTime: new Date().toISOString(),
    time: 1,
    request: {
      method: "GET",
      url,
      headers: [],
      queryString: [],
    },
    response: {
      status: 200,
      headers: [],
      content: { size: 0, text: "" },
    },
  };
}

describe("filterHarByScope", () => {
  it("keeps target registrable-domain entries and drops third-party hosts", () => {
    const ctx = {
      target: "https://app.example.com",
      session: {
        targets: ["https://app.example.com"],
        config: {},
      },
    } as ToolContext;

    const filtered = filterHarByScope(
      [
        entry("https://app.example.com/api/me"),
        entry("https://api.example.com/api/me"),
        entry("https://analytics.example.net/beacon"),
      ],
      ctx,
    );

    expect(filtered.map((item) => item.request.url)).toEqual([
      "https://app.example.com/api/me",
      "https://api.example.com/api/me",
    ]);
  });
});
