import { describe, expect, it } from "vitest";
import { parseHar } from "./types";

describe("parseHar", () => {
  it("parses the HAR subset Apex emits", () => {
    const har = parseHar({
      log: {
        version: "1.2",
        entries: [
          {
            _id: "entry-1",
            startedDateTime: new Date().toISOString(),
            time: 12,
            request: {
              method: "GET",
              url: "https://app.example.com/api/me",
              headers: [{ name: "Cookie", value: "sid=abc" }],
              queryString: [],
            },
            response: {
              status: 200,
              headers: [{ name: "Content-Type", value: "application/json" }],
              content: {
                size: 2,
                mimeType: "application/json",
                text: "{}",
              },
            },
          },
        ],
      },
    });

    expect(har.log.entries[0].request.headers[0].value).toBe("sid=abc");
  });
});
