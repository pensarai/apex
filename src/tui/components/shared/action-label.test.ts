import { describe, expect, it } from "vitest";
import type { PendingApproval } from "../../../core/operator";
import { deriveActionLabel, deriveApprovedActionLabel } from "./action-label";

function makeApproval(
  overrides: Partial<PendingApproval> = {},
): PendingApproval {
  return {
    id: "apr_1777922893504_0d385b65",
    toolName: "execute_command",
    toolCallId: "tc_test_1",
    args: { command: "ls -la" },
    tier: 1,
    timestamp: 0,
    ...overrides,
  };
}

describe("deriveApprovedActionLabel", () => {
  it("returns args.toolCallDescription when present and non-empty", () => {
    const approval = makeApproval({
      args: {
        command: "ffuf -u https://example.com/FUZZ -w wordlist.txt",
        toolCallDescription: "Running ffuf against example.com",
      },
    });

    expect(deriveApprovedActionLabel(approval)).toBe(
      "Running ffuf against example.com",
    );
  });

  it("trims whitespace from the description", () => {
    const approval = makeApproval({
      args: {
        toolCallDescription: "  Running scan  \n",
      },
    });

    expect(deriveApprovedActionLabel(approval)).toBe("Running scan");
  });

  it("falls back to getToolSummary when description is absent", () => {
    const approval = makeApproval({
      toolName: "execute_command",
      args: { command: "ls -la" },
    });

    expect(deriveApprovedActionLabel(approval)).toBe("$ ls -la");
  });

  it("falls back to getToolSummary when description is an empty string", () => {
    const approval = makeApproval({
      toolName: "http_request",
      args: {
        url: "https://example.com/api/users",
        method: "GET",
        toolCallDescription: "",
      },
    });

    expect(deriveApprovedActionLabel(approval)).toBe(
      "GET https://example.com/api/users",
    );
  });

  it("falls back to getToolSummary when description is whitespace only", () => {
    const approval = makeApproval({
      toolName: "http_request",
      args: {
        url: "https://example.com/api/users",
        toolCallDescription: "   \n\t  ",
      },
    });

    expect(deriveApprovedActionLabel(approval)).toBe(
      "GET https://example.com/api/users",
    );
  });

  it("ignores a non-string toolCallDescription and falls back to summary", () => {
    const approval = makeApproval({
      toolName: "execute_command",
      args: {
        command: "ls -la",
        toolCallDescription: 42 as unknown as string,
      },
    });

    expect(deriveApprovedActionLabel(approval)).toBe("$ ls -la");
  });

  it("delegates to deriveActionLabel with the same precedence", () => {
    const approval = makeApproval({
      toolName: "execute_command",
      args: {
        command: "gobuster -u https://example.com",
        toolCallDescription: "Running gobuster against example.com",
      },
    });

    expect(deriveApprovedActionLabel(approval)).toBe(
      deriveActionLabel(approval.toolName, approval.args),
    );
  });
});

describe("deriveActionLabel", () => {
  it("returns the description when present", () => {
    expect(
      deriveActionLabel("execute_command", {
        command: "gobuster -u https://example.com",
        toolCallDescription: "Running gobuster against example.com",
      }),
    ).toBe("Running gobuster against example.com");
  });

  it("falls back to getToolSummary for execute_command in auto mode", () => {
    expect(
      deriveActionLabel("execute_command", {
        command: "gobuster -u https://example.com -w wordlist.txt",
      }),
    ).toBe("$ gobuster -u https://example.com -w wordlist.txt");
  });

  it("handles undefined args without throwing", () => {
    expect(deriveActionLabel("scratchpad", undefined)).toBe("note");
  });

  it("handles empty args gracefully (returns the tool name itself)", () => {
    expect(deriveActionLabel("custom_tool", {})).toBe("custom_tool");
  });
});
