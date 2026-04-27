import { describe, expect, it } from "vitest";
import {
  isLocalBurpMcpUrl,
  normalizeBurpMcpUrl,
  resolveBurpSuiteConfig,
} from "./burpConfig";

describe("resolveBurpSuiteConfig", () => {
  it("returns undefined when Burp is not enabled", () => {
    expect(resolveBurpSuiteConfig(undefined)).toBeUndefined();
    expect(resolveBurpSuiteConfig({ enabled: false })).toBeUndefined();
  });

  it("applies default Burp endpoints when enabled", () => {
    expect(resolveBurpSuiteConfig({ enabled: true })).toEqual({
      enabled: true,
      transport: "sse",
      proxyUrl: "http://127.0.0.1:8080",
      sseUrl: "http://127.0.0.1:9876/sse",
      mcpSseUrl: "http://127.0.0.1:9876/sse",
      mcpProxyCommand: "java",
      mcpProxyArgs: undefined,
      timeoutMs: 15000,
      allowedTargets: [],
      allowConfigMutation: false,
      ignoreTlsErrors: false,
      warnings: [],
    });
  });

  it("preserves explicit Burp settings", () => {
    expect(
      resolveBurpSuiteConfig({
        enabled: true,
        proxyUrl: "http://127.0.0.1:8081",
        mcpSseUrl: "http://127.0.0.1:9877",
        mcpProxyCommand: "/path/to/java",
        mcpProxyArgs: ["-jar", "/tmp/mcp-proxy.jar"],
        ignoreTlsErrors: true,
      }),
    ).toEqual({
      enabled: true,
      transport: "sse",
      proxyUrl: "http://127.0.0.1:8081",
      mcpSseUrl: "http://127.0.0.1:9877",
      sseUrl: "http://127.0.0.1:9877",
      mcpProxyCommand: "/path/to/java",
      mcpProxyArgs: ["-jar", "/tmp/mcp-proxy.jar"],
      timeoutMs: 15000,
      allowedTargets: [],
      allowConfigMutation: false,
      ignoreTlsErrors: true,
      warnings: [],
    });
  });

  it("merges user config with session overrides", () => {
    expect(
      resolveBurpSuiteConfig(
        { enabled: true, timeoutMs: 10_000 },
        {
          enabled: true,
          sseUrl: "http://127.0.0.1:9878/sse",
          allowedTargets: ["example.com"],
          allowConfigMutation: true,
        },
      ),
    ).toMatchObject({
      sseUrl: "http://127.0.0.1:9878/sse",
      timeoutMs: 10_000,
      allowedTargets: ["example.com"],
      allowConfigMutation: true,
    });
  });

  it("validates URL format and local endpoint detection", () => {
    expect(normalizeBurpMcpUrl("http://127.0.0.1:9876/sse/")).toBe(
      "http://127.0.0.1:9876/sse",
    );
    expect(isLocalBurpMcpUrl("http://localhost:9876/sse")).toBe(true);
    expect(isLocalBurpMcpUrl("https://burp.example.com/sse")).toBe(false);
    expect(() => normalizeBurpMcpUrl("file:///tmp/socket")).toThrow(
      "Burp MCP URL must use http or https.",
    );
  });
});
