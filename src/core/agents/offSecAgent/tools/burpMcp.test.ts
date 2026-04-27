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

  it("parses target details from raw HTTP Host header with common HTTP port", () => {
    expect(
      parseRawHttpTarget("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"),
    ).toEqual({
      targetHostname: "example.com",
      targetPort: 8080,
      usesHttps: false,
    });
  });

  it("defaults raw HTTP Host headers without ports to HTTP", () => {
    expect(
      parseRawHttpTarget("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    ).toEqual({
      targetHostname: "example.com",
      targetPort: 80,
      usesHttps: false,
    });
  });

  it("preserves HTTPS inference for explicit port 443", () => {
    expect(
      parseRawHttpTarget("GET / HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
    ).toEqual({
      targetHostname: "example.com",
      targetPort: 443,
      usesHttps: true,
    });
  });

  it("treats common development ports as HTTP", () => {
    expect(
      parseRawHttpTarget("GET / HTTP/1.1\r\nHost: example.com:3000\r\n\r\n"),
    ).toEqual({
      targetHostname: "example.com",
      targetPort: 3000,
      usesHttps: false,
    });
  });

  it("returns null when a raw HTTP request has no Host header", () => {
    expect(parseRawHttpTarget("GET / HTTP/1.1\r\n\r\n")).toBeNull();
  });
});
