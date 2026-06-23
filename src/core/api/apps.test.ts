import { beforeEach, describe, expect, it, vi } from "vitest";

const apiRequest = vi.hoisted(() => vi.fn());

vi.mock("./apiClient", () => ({ apiRequest }));

import { updateEndpoint } from "./apps";

const ENDPOINT_ID = "55555555-5555-5555-5555-555555555555";
const NEW_APP_ID = "66666666-6666-6666-6666-666666666666";

describe("updateEndpoint", () => {
  beforeEach(() => {
    apiRequest.mockReset();
    apiRequest.mockResolvedValue({ id: ENDPOINT_ID });
  });

  it("PATCHes the endpoint and forwards applicationId when moving apps", async () => {
    await updateEndpoint(ENDPOINT_ID, { applicationId: NEW_APP_ID });

    expect(apiRequest).toHaveBeenCalledWith(
      "PATCH",
      `/endpoints/${ENDPOINT_ID}`,
      { applicationId: NEW_APP_ID },
    );
  });

  it("forwards applicationId alongside other endpoint fields", async () => {
    await updateEndpoint(ENDPOINT_ID, {
      applicationId: NEW_APP_ID,
      description: "moved",
    });

    expect(apiRequest).toHaveBeenCalledWith(
      "PATCH",
      `/endpoints/${ENDPOINT_ID}`,
      { applicationId: NEW_APP_ID, description: "moved" },
    );
  });
});
