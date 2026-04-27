import { describe, expect, it } from "vitest";
import { extractMcpText, parseRawHttpTarget } from "./burpMcp";

describe("Burp MCP helpers", () => {
  it("extracts text content from MCP tool results", () => {
    expect(
      extractMcpText({
        content: [
          { type: "text", text: "first" },
          { type: "text", text: "second" },
        ],
      }),
    ).toBe("first\nsecond");
  });

  it("parses target details from raw HTTP Host header", () => {
    expect(
      parseRawHttpTarget("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"),
    ).toEqual({
      targetHostname: "example.com",
      targetPort: 8080,
      usesHttps: true,
    });
  });

  it("returns null when a raw HTTP request has no Host header", () => {
    expect(parseRawHttpTarget("GET / HTTP/1.1\r\n\r\n")).toBeNull();
  });
});
