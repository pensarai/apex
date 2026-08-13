import { beforeEach, describe, expect, it, vi } from "vitest";

const auth = vi.hoisted(() => ({
  ensureValidToken: vi.fn(),
}));

vi.mock("../../../core/auth", () => auth);

import { resolveStoredAuth } from "./auth-flow-logic";

describe("resolveStoredAuth", () => {
  beforeEach(() => {
    auth.ensureValidToken.mockReset();
  });

  it("requires reauthentication when stored credentials cannot be refreshed", async () => {
    auth.ensureValidToken.mockResolvedValue(null);

    await expect(
      resolveStoredAuth({
        accessToken: "expired-access-token",
        refreshToken: "stale-refresh-token",
        workspaceId: "workspace-1",
      }),
    ).resolves.toEqual({ status: "reauthenticate" });
  });

  it("accepts a valid connection with a selected workspace", async () => {
    auth.ensureValidToken.mockResolvedValue({
      token: "valid-access-token",
      type: "workos",
    });

    await expect(
      resolveStoredAuth({
        accessToken: "valid-access-token",
        workspaceId: "workspace-1",
      }),
    ).resolves.toEqual({ status: "connected" });
  });

  it("continues workspace selection with the refreshed access token", async () => {
    auth.ensureValidToken.mockResolvedValue({
      token: "refreshed-access-token",
      type: "workos",
    });

    await expect(
      resolveStoredAuth({
        accessToken: "expired-access-token",
        refreshToken: "valid-refresh-token",
      }),
    ).resolves.toEqual({
      status: "select-workspace",
      accessToken: "refreshed-access-token",
    });
  });
});
