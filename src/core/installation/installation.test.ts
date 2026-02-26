import { describe, it, expect, vi, afterEach } from "vitest";
import {
  getCurrentVersion,
  getLatestVersion,
  getVersion,
  detectInstallMethod,
  getUpgradeCommandString,
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
// getVersion
// ---------------------------------------------------------------------------

describe("getVersion", () => {
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
    const version = await getVersion();
    expect(version).toBe("1.2.3-custom");
  });

  it("fetches version from npm registry when env var is not set", async () => {
    delete process.env["APEX_VERSION"];
    const mockFetch = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(JSON.stringify({ version: "9.9.9" }), { status: 200 }),
      );
    const version = await getVersion();
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
      "brew upgrade pensarai/apex/apex",
    );
  });

  it("returns curl command for binary method", () => {
    const cmd = getUpgradeCommandString("binary");
    expect(cmd).toContain("curl");
    expect(cmd).toContain("pensarai.com/install.sh");
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

  it("includes manual command on upgrade failure", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ version: "99.99.99" }), { status: 200 }),
    );

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
