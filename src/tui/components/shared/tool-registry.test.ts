import { describe, expect, it } from "vitest";
import { getToolDisplayLabel, getToolSummary } from "./tool-registry";

describe("getToolDisplayLabel", () => {
  it("returns command summary for execute_command", () => {
    expect(
      getToolDisplayLabel("execute_command", {
        command: "rg --files . | head",
      }),
    ).toBe("$ rg --files . | head");
  });

  it("returns empty command summary when command is missing", () => {
    expect(getToolSummary("execute_command", {})).toBe("$ ");
  });

  it("returns method + URL for http_request", () => {
    expect(
      getToolDisplayLabel("http_request", {
        method: "GET",
        url: "https://example.com",
      }),
    ).toBe("GET https://example.com");
  });

  it("falls back to tool name for unknown tools", () => {
    expect(getToolDisplayLabel("unknown_tool", {})).toBe("unknown_tool");
  });

  it("uses first arg value for unregistered tools with args", () => {
    expect(
      getToolDisplayLabel("custom_tool", { target: "https://example.com" }),
    ).toBe("custom_tool https://example.com");
  });
});
