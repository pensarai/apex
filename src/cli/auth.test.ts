import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  ensureValidToken,
  getConfig,
  getPensarApiUrl,
  isConnected,
  updateConfig,
} = vi.hoisted(() => ({
  ensureValidToken: vi.fn(),
  getConfig: vi.fn(),
  getPensarApiUrl: vi.fn(() => "https://console.example.com"),
  isConnected: vi.fn(() => true),
  updateConfig: vi.fn(),
}));

vi.mock("../core/api", () => ({
  getPensarApiUrl,
  getPensarConsoleUrl: () => "https://console.example.com",
}));

vi.mock("../core/auth", () => ({
  AuthSessionExpiredError: class AuthSessionExpiredError extends Error {},
  disconnect: vi.fn(),
  ensureValidToken,
  fetchWorkspaces: vi.fn(),
  isConnected,
  pollForWorkspaceCreation: vi.fn(),
  pollLegacyToken: vi.fn(),
  pollWorkOSToken: vi.fn(),
  saveWorkOSSession: vi.fn(),
  selectWorkspace: vi.fn(),
  startDeviceFlow: vi.fn(),
}));

vi.mock("../core/auth/token", () => ({
  AuthRefreshError: class AuthRefreshError extends Error {},
}));

vi.mock("../core/config", () => ({
  config: { get: getConfig, update: updateConfig },
}));

const originalArgv = process.argv;

beforeEach(() => {
  vi.resetModules();
  ensureValidToken.mockReset();
  getConfig.mockReset();
  getPensarApiUrl.mockClear();
  isConnected.mockClear();
  updateConfig.mockReset();
  process.argv = ["bun", "auth.ts", "status"];
});

afterEach(() => {
  process.argv = originalArgv;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function runStatus(): Promise<ReturnType<typeof vi.spyOn>> {
  const consoleLog = vi.spyOn(console, "log").mockImplementation(() => {});
  await import("./auth");
  await vi.waitFor(() =>
    expect(consoleLog).toHaveBeenCalledWith(
      expect.stringContaining("Connected to Pensar Console"),
    ),
  );
  return consoleLog;
}

describe("login status", () => {
  it("does not resolve an API-key workspace for an active WorkOS session", async () => {
    getConfig.mockResolvedValue({
      pensarAPIKey: "legacy-key",
      workosSession: true,
    });
    ensureValidToken.mockResolvedValue({
      token: "workos-token",
      type: "workos",
    });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const consoleLog = await runStatus();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(updateConfig).not.toHaveBeenCalled();
    expect(consoleLog).toHaveBeenCalledWith(
      expect.stringContaining("Auth: WorkOS"),
    );
  });

  it("resolves the legacy workspace when WorkOS falls back to an API key", async () => {
    getConfig.mockResolvedValue({
      pensarAPIKey: "legacy-key",
      workosSession: true,
    });
    ensureValidToken.mockResolvedValue({
      token: "legacy-key",
      type: "legacy",
    });
    const fetchMock = vi.fn(async () =>
      Response.json({
        workspace: { id: "workspace-1", name: "Workspace", slug: "workspace" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const consoleLog = await runStatus();

    expect(fetchMock).toHaveBeenCalledWith(
      "https://console.example.com/auth/validate",
      { headers: { Authorization: "Bearer legacy-key" } },
    );
    expect(updateConfig).toHaveBeenCalledWith({
      workspaceId: "workspace-1",
      workspaceSlug: "workspace",
    });
    expect(consoleLog).toHaveBeenCalledWith(
      expect.stringContaining("Auth: API key"),
    );
  });
});
