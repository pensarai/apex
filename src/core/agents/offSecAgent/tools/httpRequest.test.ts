import { describe, expect, it } from "vitest";
import { buildCurlArgs, parseCurlResponse } from "./httpRequest";

describe("httpRequest curl helpers", () => {
  it("builds curl args with Burp proxy options", () => {
    expect(
      buildCurlArgs({
        url: "https://example.com/login",
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: '{"username":"test"}',
        followRedirects: true,
        timeout: 10_000,
        proxyUrl: "http://127.0.0.1:8080",
        ignoreTlsErrors: true,
      }),
    ).toEqual([
      "-i",
      "-X",
      "POST",
      "-H",
      "Content-Type: application/json",
      "-d",
      '{"username":"test"}',
      "-L",
      "--proxy",
      "http://127.0.0.1:8080",
      "-k",
      "--max-time",
      "10",
      "https://example.com/login",
    ]);
  });

  it("parses the final response when curl follows redirects", () => {
    const parsed = parseCurlResponse(
      [
        "HTTP/1.1 302 Found",
        "Location: /login",
        "",
        "",
        "HTTP/1.1 200 OK",
        "Content-Type: text/plain",
        "",
        "done",
      ].join("\n"),
      "https://example.com",
    );

    expect(parsed).toMatchObject({
      success: true,
      status: 200,
      statusText: "OK",
      headers: { "content-type": "text/plain" },
      body: "done",
      redirected: true,
    });
  });
});
