import { describe, it, expect, vi, afterEach } from "vitest";
import {
  getCurrentVersion,
  getLatestVersion,
  resolveVersion,
  isNewerVersion,
  detectInstallMethod,
  getUpgradeCommandString,
  checkForUpdate,
  upgrade,
} from "./index";
import packageJson from "../../../package.json";

vi.mock("child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("child_process")>();
  return { ...actual, spawnSync: vi.fn(actual.spawnSync) };
});

// ---------------------------------------------------------------------------
// getCurrentVersion
// ---------------------------------------------------------------------------

describe("getCurrentVersion", () => {
  it("returns the version from package.json", () => {
    expect(getCurrentVersion()).toBe(packageJson.version);
  });

  it("returns a valid semver-like string", () => {
    const version = getCurrentVersion();
    expect(version).toMatch(/^\d+\.\d+\.\d+/);
  });
});

// ---------------------------------------------------------------------------
// resolveVersion
// ---------------------------------------------------------------------------

describe("resolveVersion", () => {
  const originalEnv = process.env["APEX_VERSION"];

  afterEach(() => {
    if (originalEnv !== undefined) {
      process.env["APEX_VERSION"] = originalEnv;
    } else {
      delete process.env["APEX_VERSION"];
    }
    vi.restoreAllMocks();
  });

  it("returns APEX_VERSION env var when set", async () => {
    process.env["APEX_VERSION"] = "1.2.3-custom";
    const version = await resolveVersion();
    expect(version).toBe("1.2.3-custom");
  });

  it("delegates to getLatestVersion when env var is not set", async () => {
    delete process.env["APEX_VERSION"];
    const mockFetch = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(JSON.stringify({ version: "9.9.9" }), { status: 200 }),
      );
    const version = await resolveVersion();
    expect(version).toBe("9.9.9");
    expect(mockFetch).toHaveBeenCalledWith(
      "https://registry.npmjs.org/@pensar/apex/latest",
    );
  });
});

// ---------------------------------------------------------------------------
// getLatestVersion
// ---------------------------------------------------------------------------

describe("getLatestVersion", () => {
  afterEach(() => vi.restoreAllMocks());

  it("returns the latest version from npm registry", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ version: "1.0.0" }), { status: 200 }),
    );
    const version = await getLatestVersion();
    expect(version).toBe("1.0.0");
  });

  it("throws on non-ok response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("not found", { status: 404, statusText: "Not Found" }),
    );
    await expect(getLatestVersion()).rejects.toThrow("Not Found");
  });
});

// ---------------------------------------------------------------------------
// isNewerVersion
// ---------------------------------------------------------------------------

describe("isNewerVersion", () => {
  it("returns true when latest has higher patch", () => {
    expect(isNewerVersion("0.0.66", "0.0.67")).toBe(true);
  });

  it("returns true when latest has higher minor", () => {
    expect(isNewerVersion("0.1.0", "0.2.0")).toBe(true);
  });

  it("returns true when latest has higher major", () => {
    expect(isNewerVersion("1.0.0", "2.0.0")).toBe(true);
  });

  it("returns false when versions are equal", () => {
    expect(isNewerVersion("0.0.67", "0.0.67")).toBe(false);
  });

  it("returns false when current is newer than latest", () => {
    expect(isNewerVersion("0.0.67", "0.0.66")).toBe(false);
  });

  it("returns false when current major is higher", () => {
    expect(isNewerVersion("2.0.0", "1.9.9")).toBe(false);
  });

  it("handles versions with different segment counts", () => {
    expect(isNewerVersion("1.0", "1.0.1")).toBe(true);
    expect(isNewerVersion("1.0.1", "1.0")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// detectInstallMethod
// ---------------------------------------------------------------------------

describe("detectInstallMethod", () => {
  const origExecPath = process.execPath;
  const origArgv = [...process.argv];

  afterEach(() => {
    Object.defineProperty(process, "execPath", {
      value: origExecPath,
      writable: true,
    });
    process.argv = [...origArgv];
    vi.restoreAllMocks();
  });

  it("detects homebrew from execPath", () => {
    Object.defineProperty(process, "execPath", {
      value: "/opt/homebrew/bin/bun",
      writable: true,
    });
    expect(detectInstallMethod()).toBe("homebrew");
  });

  it("detects homebrew from Cellar in execPath", () => {
    Object.defineProperty(process, "execPath", {
      value: "/opt/homebrew/Cellar/apex/0.1.0/bin/pensar",
      writable: true,
    });
    expect(detectInstallMethod()).toBe("homebrew");
  });

  it("detects npm from node_modules in argv[1]", () => {
    Object.defineProperty(process, "execPath", {
      value: "/usr/local/bin/node",
      writable: true,
    });
    process.argv[1] = "/usr/local/lib/node_modules/@pensar/apex/bin/pensar.js";
    expect(detectInstallMethod()).toBe("npm");
  });

  it("detects npm from npx in argv[1]", () => {
    Object.defineProperty(process, "execPath", {
      value: "/usr/local/bin/node",
      writable: true,
    });
    process.argv[1] = "/home/user/.npm/_npx/abc/node_modules/.bin/pensar";
    expect(detectInstallMethod()).toBe("npm");
  });

  it("detects npm via spawnSync fallback when path heuristics miss", async () => {
    Object.defineProperty(process, "execPath", {
      value: "/usr/local/bin/node",
      writable: true,
    });
    process.argv[1] = "/usr/local/bin/pensar";

    // eslint-disable-next-line no-restricted-syntax -- dynamic import for test mocking
    const { spawnSync } = await import("child_process");
    const mockedSpawnSync = vi.mocked(spawnSync);
    mockedSpawnSync.mockReturnValue({
      status: 0,
      stdout: "└── @pensar/apex@0.1.0",
      stderr: "",
      pid: 0,
      output: [],
      signal: null,
    });

    expect(detectInstallMethod()).toBe("npm");
    expect(mockedSpawnSync).toHaveBeenCalledWith(
      "npm",
      ["list", "-g", "@pensar/apex", "--depth=0"],
      expect.objectContaining({ encoding: "utf-8" }),
    );
  });

  it("returns binary when all heuristics fail", async () => {
    Object.defineProperty(process, "execPath", {
      value: "/usr/local/bin/node",
      writable: true,
    });
    process.argv[1] = "/usr/local/bin/pensar";

    // eslint-disable-next-line no-restricted-syntax -- dynamic import for test mocking
    const { spawnSync } = await import("child_process");
    const mockedSpawnSync = vi.mocked(spawnSync);
    mockedSpawnSync.mockReturnValue({
      status: 1,
      stdout: "",
      stderr: "",
      pid: 0,
      output: [],
      signal: null,
    });

    expect(detectInstallMethod()).toBe("binary");
  });
});

// ---------------------------------------------------------------------------
// getUpgradeCommandString
// ---------------------------------------------------------------------------

describe("getUpgradeCommandString", () => {
  it("returns npm install command for npm method", () => {
    expect(getUpgradeCommandString("npm")).toBe(
      "npm install -g @pensar/apex@latest",
    );
  });

  it("returns brew upgrade command for homebrew method", () => {
    expect(getUpgradeCommandString("homebrew")).toBe(
      "brew upgrade pensarai/tap/apex",
    );
  });

  it("returns curl command for binary method", () => {
    const cmd = getUpgradeCommandString("binary");
    expect(cmd).toContain("curl");
    expect(cmd).toContain("pensarai.com/install.sh");
  });
});

// ---------------------------------------------------------------------------
// checkForUpdate
// ---------------------------------------------------------------------------

describe("checkForUpdate", () => {
  afterEach(() => vi.restoreAllMocks());

  it("reports no update when versions match", async () => {
    const current = getCurrentVersion();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ version: current }), { status: 200 }),
    );

    const result = await checkForUpdate();
    expect(result.updateAvailable).toBe(false);
    expect(result.currentVersion).toBe(current);
    expect(result.latestVersion).toBe(current);
  });

  it("reports update available when latest is greater", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ version: "99.99.99" }), { status: 200 }),
    );

    const result = await checkForUpdate();
    expect(result.updateAvailable).toBe(true);
    expect(result.currentVersion).toBe(getCurrentVersion());
    expect(result.latestVersion).toBe("99.99.99");
  });

  it("reports no update when current is newer than latest", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ version: "0.0.1" }), { status: 200 }),
    );

    const result = await checkForUpdate();
    expect(result.updateAvailable).toBe(false);
    expect(result.latestVersion).toBe("0.0.1");
  });

  it("returns no update on network failure", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));

    const result = await checkForUpdate();
    expect(result.updateAvailable).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// upgrade (integration of version check + upgrade logic)
// ---------------------------------------------------------------------------

describe("upgrade", () => {
  afterEach(() => vi.restoreAllMocks());

  it("reports already up to date when versions match", async () => {
    const current = getCurrentVersion();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ version: current }), { status: 200 }),
    );

    const result = await upgrade();
    expect(result.success).toBe(true);
    expect(result.fromVersion).toBe(current);
    expect(result.toVersion).toBe(current);
    expect(result.message).toContain("Already on the latest version");
  });

  it("returns failure when version check fails", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network error"));

    const result = await upgrade();
    expect(result.success).toBe(false);
    expect(result.message).toContain("Failed to check for updates");
  });

  it("attempts upgrade when a newer version is available", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ version: "99.99.99" }), { status: 200 }),
    );

    // eslint-disable-next-line no-restricted-syntax -- dynamic import for test mocking
    const { spawnSync } = await import("child_process");
    const mockedSpawnSync = vi.mocked(spawnSync);
    mockedSpawnSync.mockReturnValue({
      status: 0,
      stdout: "upgraded successfully",
      stderr: "",
      pid: 0,
      output: [],
      signal: null,
    });

    const result = await upgrade();
    expect(result.success).toBe(true);
    expect(result.fromVersion).toBe(getCurrentVersion());
    expect(result.toVersion).toBe("99.99.99");
    expect(result.message).toContain("Upgraded from");
  });

  it("uses stdio inherit when interactive is true", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ version: "99.99.99" }), { status: 200 }),
    );

    // eslint-disable-next-line no-restricted-syntax -- dynamic import for test mocking
    const { spawnSync } = await import("child_process");
    const mockedSpawnSync = vi.mocked(spawnSync);
    mockedSpawnSync.mockReturnValue({
      status: 0,
      stdout: "",
      stderr: "",
      pid: 0,
      output: [],
      signal: null,
    });

    await upgrade({ interactive: true });

    expect(mockedSpawnSync).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(Array),
      expect.objectContaining({ stdio: "inherit" }),
    );
  });

  it("uses stdio pipe when interactive is false", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ version: "99.99.99" }), { status: 200 }),
    );

    // eslint-disable-next-line no-restricted-syntax -- dynamic import for test mocking
    const { spawnSync } = await import("child_process");
    const mockedSpawnSync = vi.mocked(spawnSync);
    mockedSpawnSync.mockReturnValue({
      status: 0,
      stdout: "",
      stderr: "",
      pid: 0,
      output: [],
      signal: null,
    });

    await upgrade({ interactive: false });

    expect(mockedSpawnSync).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(Array),
      expect.objectContaining({ stdio: "pipe" }),
    );
  });

  it("includes manual command on upgrade failure", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ version: "99.99.99" }), { status: 200 }),
    );

    // eslint-disable-next-line no-restricted-syntax -- dynamic import for test mocking
    const { spawnSync } = await import("child_process");
    const mockedSpawnSync = vi.mocked(spawnSync);
    mockedSpawnSync.mockReturnValue({
      status: 1,
      stdout: "",
      stderr: "permission denied",
      pid: 0,
      output: [],
      signal: null,
    });

    const result = await upgrade();
    expect(result.success).toBe(false);
    expect(result.message).toContain("permission denied");
    expect(result.message).toContain("You can upgrade manually");
  });
});
