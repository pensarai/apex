import { beforeEach, describe, expect, it, vi } from "vitest";

const apiRequest = vi.hoisted(() => vi.fn());

vi.mock("./apiClient", () => ({ apiRequest }));

import { createEndpoint, updateEndpoint } from "./apps";

const APP_ID = "44444444-4444-4444-4444-444444444444";
const ENDPOINT_ID = "55555555-5555-5555-5555-555555555555";
const NEW_APP_ID = "66666666-6666-6666-6666-666666666666";

describe("createEndpoint", () => {
  beforeEach(() => {
    apiRequest.mockReset();
    apiRequest.mockResolvedValue({ id: ENDPOINT_ID });
  });

  it("forwards the endpoint transport classification", async () => {
    await createEndpoint(APP_ID, {
      endpoint: "/account.v1.AccountService/GetAccount",
      description: "Fetch an account",
      type: "api-endpoint",
      transport: "grpc",
    });

    expect(apiRequest).toHaveBeenCalledWith(
      "POST",
      `/apps/${APP_ID}/endpoints`,
      {
        endpoint: "/account.v1.AccountService/GetAccount",
        description: "Fetch an account",
        type: "api-endpoint",
        transport: "grpc",
      },
    );
  });
});

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

  it("forwards transport-only endpoint repairs", async () => {
    await updateEndpoint(ENDPOINT_ID, { transport: "connect" });

    expect(apiRequest).toHaveBeenCalledWith(
      "PATCH",
      `/endpoints/${ENDPOINT_ID}`,
      { transport: "connect" },
    );
  });
});
