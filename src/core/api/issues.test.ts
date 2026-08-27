import { beforeEach, describe, expect, it, vi } from "vitest";

const apiRequest = vi.hoisted(() => vi.fn());

vi.mock("./apiClient", () => ({ apiRequest }));

import type { IssueDetail, IssueSummary } from "./issues";
import { getIssue, listIssues, retestIssue } from "./issues";

const ISSUE_ID = "11111111-1111-1111-1111-111111111111";

const ISSUE_SUMMARY: IssueSummary = {
  id: ISSUE_ID,
  issueLabel: "VULN-000123",
  title: "Reflected XSS",
  severity: "high",
  status: "open",
  location: "src/routes/search.ts",
  url: "https://console.pensar.dev/acme/VULN-000123",
};

describe("retestIssue", () => {
  beforeEach(() => {
    apiRequest.mockReset();
    apiRequest.mockResolvedValue({
      issueId: ISSUE_ID,
      sessionId: "22222222-2222-2222-2222-222222222222",
      status: "queued",
      message: "Issue retest queued",
    });
  });

  it("POSTs to the issue retest endpoint", async () => {
    await retestIssue(ISSUE_ID);

    expect(apiRequest).toHaveBeenCalledWith(
      "POST",
      `/issues/${ISSUE_ID}/retest`,
    );
  });
});

describe("issue label and url", () => {
  beforeEach(() => {
    apiRequest.mockReset();
  });

  it("carries issueLabel and url through listIssues", async () => {
    apiRequest.mockResolvedValue([ISSUE_SUMMARY]);

    const [issue] = await listIssues();

    expect(issue?.issueLabel).toBe("VULN-000123");
    expect(issue?.url).toBe("https://console.pensar.dev/acme/VULN-000123");
  });

  it("allows a null issueLabel on an issue detail", async () => {
    const detail: IssueDetail = {
      ...ISSUE_SUMMARY,
      issueLabel: null,
      workspaceId: "33333333-3333-3333-3333-333333333333",
      workspaceName: "acme",
      createdAt: "2026-08-27T00:00:00.000Z",
    };
    apiRequest.mockResolvedValue(detail);

    const result = await getIssue(ISSUE_ID);

    expect(result.issueLabel).toBeNull();
    expect(result.url).toBe(ISSUE_SUMMARY.url);
  });
});
