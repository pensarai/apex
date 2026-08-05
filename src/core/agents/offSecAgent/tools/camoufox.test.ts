import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CAMOUFOX_OPTIONS,
  COMPUTER_USE_VIEWPORT_SIZE,
  camoufoxWindowOptions,
  ENDPOINT_DISPLAY_BASE,
  ENDPOINT_VIEWPORT_SIZE,
  MEMORY_FIREFOX_PREFS,
  parseDisplayNumber,
  parseViewportSize,
  resolveCamoufoxLaunchOptions,
  viewportSizeForDisplay,
} from "./camoufox";

const launchOptionsMock = vi.fn();

vi.mock("camoufox-js", () => ({
  launchOptions: (...args: unknown[]) => launchOptionsMock(...args),
}));

afterEach(() => {
  launchOptionsMock.mockReset();
});

describe("display-tier viewport helpers", () => {
  it("parses WIDTH,HEIGHT viewport strings", () => {
    expect(parseViewportSize("1280,720")).toEqual([1280, 720]);
    expect(parseViewportSize(" 1920,1080 ")).toEqual([1920, 1080]);
    expect(parseViewportSize("bad")).toBeUndefined();
    expect(parseViewportSize("0,720")).toBeUndefined();
  });

  it("parses :N display strings", () => {
    expect(parseDisplayNumber(":0")).toBe(0);
    expect(parseDisplayNumber(":11")).toBe(11);
    expect(parseDisplayNumber(":10.0")).toBe(10);
    expect(parseDisplayNumber(undefined)).toBeUndefined();
    expect(parseDisplayNumber("DISPLAY")).toBeUndefined();
  });

  it("maps endpoint-tier displays to 720p and everything else to 1080p", () => {
    expect(ENDPOINT_DISPLAY_BASE).toBe(10);
    expect(viewportSizeForDisplay(":11")).toBe(ENDPOINT_VIEWPORT_SIZE);
    expect(viewportSizeForDisplay(":10")).toBe(ENDPOINT_VIEWPORT_SIZE);
    expect(viewportSizeForDisplay(":0")).toBe(COMPUTER_USE_VIEWPORT_SIZE);
    expect(viewportSizeForDisplay(":9")).toBe(COMPUTER_USE_VIEWPORT_SIZE);
    expect(viewportSizeForDisplay(undefined)).toBe(COMPUTER_USE_VIEWPORT_SIZE);
  });

  it("builds fingerprint-coherent window + screen constraints", () => {
    expect(camoufoxWindowOptions([1280, 720])).toEqual({
      window: [1280, 720],
      screen: {
        minWidth: 1280,
        maxWidth: 1280,
        minHeight: 720,
        maxHeight: 720,
      },
    });
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

  it("forwards a fixed window and matching screen constraints when provided", async () => {
    launchOptionsMock.mockResolvedValue({
      executablePath: "/opt/camoufox/camoufox-bin",
      args: [],
      env: {},
      firefoxUserPrefs: {},
      headless: false,
    });

    await resolveCamoufoxLaunchOptions(false, { window: [1280, 720] });

    expect(launchOptionsMock).toHaveBeenCalledWith({
      ...CAMOUFOX_OPTIONS,
      headless: false,
      window: [1280, 720],
      screen: {
        minWidth: 1280,
        maxWidth: 1280,
        minHeight: 720,
        maxHeight: 720,
      },
    });
  });
});
