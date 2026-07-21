import { beforeEach, describe, expect, it, vi } from "vitest";

const apiRequest = vi.hoisted(() => vi.fn());

vi.mock("./apiClient", () => ({ apiRequest }));

import { retestIssue } from "./issues";

const ISSUE_ID = "11111111-1111-1111-1111-111111111111";

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
