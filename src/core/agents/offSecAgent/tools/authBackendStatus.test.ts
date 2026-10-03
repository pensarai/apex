import assert from "node:assert/strict";
import { describe, expect, it, vi } from "vitest";
import { LocalBackends } from "../../../tools/backends/local";
import type { HttpResponse } from "../../../tools/backends/types";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { detectAuthScheme } from "./detectAuthScheme";
import { probeAuthEndpoints } from "./probeAuthEndpoints";
import type { ToolContext } from "./types";

const options = { toolCallId: "test", messages: [] };
const unauthorized: HttpResponse = {
  success: false,
  status: 401,
  statusText: "Unauthorized",
  headers: { "www-authenticate": 'Basic realm="protected"' },
  body: "credentials required",
  url: "https://example.com/",
  redirected: false,
};

function context(response: HttpResponse): ToolContext {
  const ctx: ToolContext = {
    subagentSpawner: inProcessSubagentSpawner,
    agentCwd: "/tmp/auth-status",
    target: "https://example.com",
    session: {
      id: "ses_auth_status",
      version: "1.0.0",
      targets: ["https://example.com"],
      time: { created: 1, updated: 1 },
      rootPath: "/tmp/auth-status",
      logsPath: "/tmp/auth-status/logs",
      findingsPath: "/tmp/auth-status/findings",
      scratchpadPath: "/tmp/auth-status/scratchpad",
      pocsPath: "/tmp/auth-status/pocs",
      config: {},
    },
  };
  ctx.backends = {
    ...LocalBackends(ctx),
    http: { request: vi.fn(async () => response) },
  };
  return ctx;
}

describe("auth discovery through injected HTTP backends", () => {
  it("detects Basic auth from a completed HTTP 401 marked unsuccessful", async () => {
    const tool = detectAuthScheme(context(unauthorized));
    assert(tool.execute);
    const result = await tool.execute(
      { endpoint: unauthorized.url, toolCallDescription: "detect auth" },
      options,
    );
    expect(result).toMatchObject({
      success: true,
      scheme: { method: "basic" },
    });
  });

  it("keeps 401 GET and POST responses as auth endpoint evidence", async () => {
    const tool = probeAuthEndpoints(context(unauthorized));
    assert(tool.execute);
    const result = await tool.execute(
      { baseUrl: unauthorized.url, toolCallDescription: "probe auth" },
      options,
    );
    expect(result).toMatchObject({
      success: true,
      recommendedMethod: "GET (with Basic Auth header)",
    });
    expect(result).toMatchObject({
      endpoints: expect.arrayContaining([
        expect.objectContaining({
          methods: ["GET", "POST"],
          authIndicators: expect.arrayContaining([
            "requires auth (401)",
            "HTTP Basic Auth",
            "invalid credentials (401)",
          ]),
        }),
      ]),
    });
  });

  it("does not turn an incomplete transfer into discovered auth evidence", async () => {
    const response: HttpResponse = {
      ...unauthorized,
      error: "body timeout",
      capture: {
        complete: false,
        stopReason: "timeout",
        capturedBytes: 0,
        capturedBytesBasis: "raw",
      },
    };
    const ctx = context(response);
    const detect = detectAuthScheme(ctx);
    assert(detect.execute);
    const detected = await detect.execute(
      { endpoint: response.url, toolCallDescription: "detect auth" },
      options,
    );
    expect(detected).toMatchObject({ success: false, error: "body timeout" });
    const probe = probeAuthEndpoints(ctx);
    assert(probe.execute);
    const probed = await probe.execute(
      { baseUrl: response.url, toolCallDescription: "probe auth" },
      options,
    );
    expect(probed).toMatchObject({ endpoints: [] });
  });
});
