import { beforeEach, describe, expect, it, vi } from "vitest";

const apiRequest = vi.hoisted(() => vi.fn());

vi.mock("./apiClient", () => ({ apiRequest }));

import { createIssueComment, listIssueComments } from "./issues";

const ISSUE_ID = "11111111-1111-1111-1111-111111111111";

describe("listIssueComments", () => {
  beforeEach(() => {
    apiRequest.mockReset();
    apiRequest.mockResolvedValue({ comments: [], pagination: {} });
  });

  it("GETs the issue's comment sub-resource", async () => {
    await listIssueComments(ISSUE_ID);

    expect(apiRequest).toHaveBeenCalledWith(
      "GET",
      `/issues/${ISSUE_ID}/comments`,
    );
  });

  it("accepts a label in place of a uuid", async () => {
    await listIssueComments("VULN-000123");

    expect(apiRequest).toHaveBeenCalledWith(
      "GET",
      "/issues/VULN-000123/comments",
    );
  });

  it("passes pagination through as query params", async () => {
    await listIssueComments(ISSUE_ID, { page: 2, pageSize: 10 });

    expect(apiRequest).toHaveBeenCalledWith(
      "GET",
      `/issues/${ISSUE_ID}/comments?page=2&pageSize=10`,
    );
  });

  it("omits the query string entirely when no options are given", async () => {
    await listIssueComments(ISSUE_ID, {});

    expect(apiRequest).toHaveBeenCalledWith(
      "GET",
      `/issues/${ISSUE_ID}/comments`,
    );
  });
});

describe("createIssueComment", () => {
  beforeEach(() => {
    apiRequest.mockReset();
    apiRequest.mockResolvedValue({ id: "c1" });
  });

  it("POSTs the body to the issue's comment sub-resource", async () => {
    await createIssueComment(ISSUE_ID, "Rescored to 7.1");

    expect(apiRequest).toHaveBeenCalledWith(
      "POST",
      `/issues/${ISSUE_ID}/comments`,
      { body: "Rescored to 7.1" },
    );
  });
});
