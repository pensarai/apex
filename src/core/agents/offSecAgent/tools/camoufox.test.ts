import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CAMOUFOX_OPTIONS,
  hasPreinstalledCamoufox,
  MEMORY_FIREFOX_PREFS,
  resolveCamoufoxLaunchOptions,
} from "./camoufox";

const launchOptionsMock = vi.fn();
const camoufoxPathMock = vi.fn();
const launchPathMock = vi.fn();

vi.mock("camoufox-js", () => ({
  launchOptions: (...args: unknown[]) => launchOptionsMock(...args),
}));

vi.mock("camoufox-js/dist/pkgman.js", () => ({
  camoufoxPath: (...args: unknown[]) => camoufoxPathMock(...args),
  launchPath: (...args: unknown[]) => launchPathMock(...args),
}));

afterEach(() => {
  launchOptionsMock.mockReset();
  camoufoxPathMock.mockReset();
  launchPathMock.mockReset();
});

describe("hasPreinstalledCamoufox", () => {
  it("uses the non-downloading path probe before checking the executable", async () => {
    camoufoxPathMock.mockReturnValue("/opt/camoufox");
    launchPathMock.mockReturnValue("/opt/camoufox/camoufox-bin");

    await expect(hasPreinstalledCamoufox()).resolves.toBe(true);
    expect(camoufoxPathMock).toHaveBeenCalledWith(false);
    expect(launchPathMock).toHaveBeenCalledOnce();
  });

  it("reports a missing or incompatible image install without throwing", async () => {
    camoufoxPathMock.mockImplementation(() => {
      throw new Error("Camoufox executable not found");
    });

    await expect(hasPreinstalledCamoufox()).resolves.toBe(false);
    expect(launchPathMock).not.toHaveBeenCalled();
  });
});

describe("resolveCamoufoxLaunchOptions", () => {
  it("layers the memory prefs on top of camoufox's fingerprint prefs", async () => {
    launchOptionsMock.mockResolvedValue({
      executablePath: "/opt/camoufox/camoufox-bin",
      args: ["--foo"],
      env: {},
      firefoxUserPrefs: { "some.fingerprint.pref": "spoofed" },
      headless: true,
    });

    const opts = await resolveCamoufoxLaunchOptions(true);

    // camoufox's own prefs are preserved…
    expect(opts.firefoxUserPrefs["some.fingerprint.pref"]).toBe("spoofed");
    // …and every memory pref is merged in.
    for (const [key, value] of Object.entries(MEMORY_FIREFOX_PREFS)) {
      expect(opts.firefoxUserPrefs[key]).toBe(value);
    }
    // Fission stays off / content pool capped — the load-bearing keys.
    expect(opts.firefoxUserPrefs["fission.autostart"]).toBe(false);
    expect(opts.firefoxUserPrefs["dom.ipc.processCount"]).toBe(1);
  });

  it("lets the memory prefs win when camoufox sets the same key", async () => {
    launchOptionsMock.mockResolvedValue({
      executablePath: "/opt/camoufox/camoufox-bin",
      args: [],
      env: {},
      // Camoufox (hypothetically) leaves Fission on — we must override it.
      firefoxUserPrefs: { "fission.autostart": true },
      headless: false,
    });

    const opts = await resolveCamoufoxLaunchOptions(false);

    expect(opts.firefoxUserPrefs["fission.autostart"]).toBe(false);
  });

  it("forwards the stealth options and headless flag to camoufox-js", async () => {
    launchOptionsMock.mockResolvedValue({
      executablePath: "/opt/camoufox/camoufox-bin",
      args: [],
      env: {},
      firefoxUserPrefs: {},
      headless: true,
    });

    await resolveCamoufoxLaunchOptions(true);

    expect(launchOptionsMock).toHaveBeenCalledWith({
      ...CAMOUFOX_OPTIONS,
      headless: true,
    });
  });
});
