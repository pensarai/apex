import { beforeEach, describe, expect, it, vi } from "vitest";

const apiRequest = vi.hoisted(() => vi.fn());

vi.mock("./apiClient", () => ({ apiRequest }));

import type { IssueDetail, IssueSummary } from "./issues";
import {
  dispatchPentest,
  getIssue,
  getIssueEvidence,
  listIssueRetests,
  listIssues,
  retestIssue,
} from "./issues";

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
      label: null,
      name: "Reflected XSS",
      findingTitle: "Reflected XSS",
      pullRequestTitle: null,
      description: null,
      severityLevel: 3,
      startLine: null,
      endLine: null,
      startLineNumber: null,
      endLineNumber: null,
      cwe: "",
      cwes: [],
      branch: null,
      cvss: null,
      application: null,
      applicationId: null,
      endpoint: null,
      endpointId: null,
      repository: null,
      introducedBy: null,
      pentestId: null,
      poc: null,
      updatedAt: "2026-08-27T00:00:00.000Z",
      closedAt: null,
      closedMethod: null,
      closedReason: null,
      closedComments: null,
      closedDisposition: null,
      duplicateOf: null,
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

describe("hosted pentest launch API", () => {
  beforeEach(() => apiRequest.mockReset());

  it("sends exact endpoint scope in the launch request", async () => {
    const input = { endpointIds: [ISSUE_ID], scanLevel: "full" as const };
    await dispatchPentest(input);
    expect(apiRequest).toHaveBeenCalledWith("POST", "/pentests", input);
  });
});

describe("finding evidence and retest reads", () => {
  beforeEach(() => {
    apiRequest.mockReset();
  });

  it("reads evidence without transforming the response", async () => {
    const response = {
      issueId: ISSUE_ID,
      poc: null,
      pocOutput: null,
      steps: null,
      attackPath: null,
      codeSnippet: null,
      codeSnippetReason: "no_repository",
    };
    apiRequest.mockResolvedValue(response);
    expect(await getIssueEvidence(ISSUE_ID)).toBe(response);
    expect(apiRequest).toHaveBeenCalledWith(
      "GET",
      `/issues/${ISSUE_ID}/evidence`,
    );
  });

  it("reads retest history without transforming the response", async () => {
    const response = [{ id: "retest-id", status: "fixed", stillExists: false }];
    apiRequest.mockResolvedValue(response);
    expect(await listIssueRetests(ISSUE_ID)).toBe(response);
    expect(apiRequest).toHaveBeenCalledWith(
      "GET",
      `/issues/${ISSUE_ID}/retests`,
    );
  });

  it("propagates authorization errors", async () => {
    apiRequest.mockRejectedValue(new Error("API error (403): Forbidden"));
    await expect(getIssueEvidence(ISSUE_ID)).rejects.toThrow("API error (403)");
  });
});
