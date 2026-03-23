import { describe, expect, it } from "vitest";
import { tryParsePartialJson } from "./message-utils";
import { getToolDisplayLabel, getToolSummary } from "./tool-registry";

describe("getToolDisplayLabel", () => {
  it("reproduces the raw execute_command summary fallback for description-only args", () => {
    const parsed = tryParsePartialJson(
      '{"toolCallDescription":"Searching repository for secrets"}',
    );

    expect(parsed).toEqual({
      toolCallDescription: "Searching repository for secrets",
    });
    expect(getToolSummary("execute_command", parsed!)).toBe("$ ");
  });

  it("prefers the human description for pending execute_command calls", () => {
    const parsed = tryParsePartialJson(
      '{"toolCallDescription":"Searching repository for secrets","command":"rg --fi',
    );

    expect(parsed).toEqual({
      toolCallDescription: "Searching repository for secrets",
      command: "rg --fi",
    });
    expect(
      getToolDisplayLabel("execute_command", parsed!, {
        preferDescription: true,
      }),
    ).toBe("Searching repository for secrets");
  });

  it("falls back to the command summary after execute_command completes", () => {
    expect(
      getToolDisplayLabel(
        "execute_command",
        {
          toolCallDescription: "Searching repository for secrets",
          command: "rg --files . | head",
        },
        { preferDescription: false },
      ),
    ).toBe("$ rg --files . | head");
  });

  it("leaves non-shell tool labels unchanged", () => {
    expect(
      getToolDisplayLabel(
        "http_request",
        {
          toolCallDescription: "Fetching homepage",
          method: "GET",
          url: "https://example.com",
        },
        { preferDescription: true },
      ),
    ).toBe("GET https://example.com");
  });
});
