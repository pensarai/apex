import type { Interface, ReadLineOptions } from "node:readline";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  createInterface,
  ensureValidToken,
  getConfig,
  isConnected,
  startDeviceFlow,
} = vi.hoisted(() => ({
  createInterface: vi.fn<(options: ReadLineOptions) => Interface>(),
  ensureValidToken: vi.fn(),
  getConfig: vi.fn(),
  isConnected: vi.fn(),
  startDeviceFlow: vi.fn(),
}));

vi.mock("node:readline", () => ({ createInterface }));
vi.mock("../core/api", () => ({
  getPensarApiUrl: () => "https://console.example.test",
  getPensarConsoleUrl: () => "https://console.example.test",
}));
vi.mock("../core/auth", () => ({
  createWorkspaceSelection: vi.fn(),
  disconnect: vi.fn(),
  ensureValidToken,
  fetchWorkspaces: vi.fn(),
  isConnected,
  pollForWorkspaceCreation: vi.fn(),
  pollLegacyToken: vi.fn(),
  pollWorkOSToken: vi.fn(),
  pollWorkspaceSelection: vi.fn(),
  selectWorkspace: vi.fn(),
  startDeviceFlow,
}));
vi.mock("../core/config", () => ({
  config: { get: getConfig, update: vi.fn() },
}));

const originalArgv = process.argv;
const originalExitCode = process.exitCode;
const originalIsTTY = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
let input: PassThrough;
let output: PassThrough;

beforeEach(async () => {
  vi.resetModules();
  vi.resetAllMocks();
  process.argv = ["bun", "auth.ts"];
  process.exitCode = undefined;
  input = new PassThrough();
  output = new PassThrough();
  const readline =
    await vi.importActual<typeof import("node:readline")>("node:readline");
  createInterface.mockImplementation((options) =>
    readline.createInterface({
      ...options,
      input,
      output,
      terminal: false,
    }),
  );
  getConfig.mockResolvedValue({
    pensarAPIKey: "fixture-key",
    workspaceSlug: "fixture-workspace",
  });
  isConnected.mockReturnValue(true);
  ensureValidToken.mockResolvedValue({ token: "fixture-key", type: "legacy" });
  startDeviceFlow.mockRejectedValue(new Error("Device flow unavailable"));
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  input.destroy();
  output.destroy();
  process.argv = originalArgv;
  process.exitCode = originalExitCode;
  if (originalIsTTY) {
    Object.defineProperty(process.stdin, "isTTY", originalIsTTY);
  } else {
    Reflect.deleteProperty(process.stdin, "isTTY");
  }
  vi.restoreAllMocks();
});

function setTTY(value: boolean | undefined): void {
  Object.defineProperty(process.stdin, "isTTY", {
    configurable: true,
    value,
  });
}

describe("login reconnect", () => {
  it.each([
    false,
    undefined,
  ])("finishes an authenticated login without prompting when stdin.isTTY=%s", async (isTTY) => {
    setTTY(isTTY);
    createInterface.mockImplementation(() => {
      throw new Error("Unexpected terminal prompt");
    });

    await import("./auth");

    expect(createInterface).not.toHaveBeenCalled();
    expect(startDeviceFlow).not.toHaveBeenCalled();
    expect(console.log).toHaveBeenCalledWith(
      "Already connected to Pensar Console.",
    );
    expect(console.log).toHaveBeenCalledWith("  Workspace: fixture-workspace");
    expect(process.exitCode).toBeUndefined();
  });

  it.each([
    { answer: "n", reconnect: false },
    { answer: " y ", reconnect: true },
    { answer: null, reconnect: false },
  ])("honors interactive answer $answer (reconnect=$reconnect)", async ({
    answer,
    reconnect,
  }) => {
    setTTY(true);
    const login = import("./auth");
    await vi.waitFor(() => expect(createInterface).toHaveBeenCalledOnce());

    input.end(answer === null ? undefined : `${answer}\n`);
    await login;

    expect(startDeviceFlow).toHaveBeenCalledTimes(reconnect ? 1 : 0);
    expect(process.exitCode).toBe(reconnect ? 1 : undefined);
  }, 1_000);

  it.each([
    false,
    true,
  ])("starts device authentication without a valid token (stored=%s)", async (stored) => {
    setTTY(false);
    isConnected.mockReturnValue(stored);
    ensureValidToken.mockResolvedValue(null);

    await import("./auth");

    expect(createInterface).not.toHaveBeenCalled();
    expect(ensureValidToken).toHaveBeenCalledTimes(stored ? 1 : 0);
    expect(startDeviceFlow).toHaveBeenCalledOnce();
    expect(startDeviceFlow).toHaveBeenCalledWith(
      "https://console.example.test",
    );
    expect(console.error).toHaveBeenCalledWith(
      "\nError: Device flow unavailable",
    );
    expect(process.exitCode).toBe(1);
  });
});
