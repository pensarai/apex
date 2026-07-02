import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CAMOUFOX_OPTIONS,
  MEMORY_FIREFOX_PREFS,
  resolveCamoufoxLaunchOptions,
} from "./camoufox";

const launchOptionsMock = vi.fn();

vi.mock("camoufox-js", () => ({
  launchOptions: (...args: unknown[]) => launchOptionsMock(...args),
}));

afterEach(() => {
  launchOptionsMock.mockReset();
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
