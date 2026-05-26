import { describe, expect, it } from "vitest";
import { diffHarEntries } from "./diff";
import type { HarEntry } from "./types";

function entry(id: string, url: string, body: string, status = 200): HarEntry {
  return {
    _id: id,
    startedDateTime: new Date().toISOString(),
    time: 1,
    request: {
      method: "GET",
      url,
      headers: [{ name: "Cookie", value: `sid=${id}` }],
      queryString: [],
    },
    response: {
      status,
      headers: [{ name: "Content-Type", value: "application/json" }],
      content: { size: body.length, text: body },
    },
  };
}

describe("diffHarEntries", () => {
  it("preserves auth context and buckets same-response candidates", () => {
    const report = diffHarEntries(
      [entry("a1", "https://app.example.com/api/users/1", '{"id":1}')],
      [entry("b1", "https://app.example.com/api/users/1", '{"id":1}')],
    );

    expect(report.candidates[0]).toMatchObject({
      bucket: "same-response",
      score: 80,
      accountA: {
        requestAuth: { cookie: "sid=a1" },
      },
      accountB: {
        requestAuth: { cookie: "sid=b1" },
      },
    });
  });

  it("records unique entries from both accounts", () => {
    const report = diffHarEntries(
      [entry("a1", "https://app.example.com/api/a", "a")],
      [entry("b1", "https://app.example.com/api/b", "b")],
    );

    expect(report.candidates.map((candidate) => candidate.bucket)).toEqual([
      "unique-to-a",
      "unique-to-b",
    ]);
  });
});
