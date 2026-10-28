import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CAMOUFOX_OPTIONS,
  camoufoxWindowOptions,
  MEMORY_FIREFOX_PREFS,
  parseDisplayNumber,
  parseViewportSize,
  resolveCamoufoxLaunchOptions,
  resolveSandboxBrowserProxy,
} from "./camoufox";

const launchOptionsMock = vi.fn();

vi.mock("camoufox-js", () => ({
  launchOptions: (...args: unknown[]) => launchOptionsMock(...args),
}));

afterEach(() => {
  launchOptionsMock.mockReset();
});

describe("resolveSandboxBrowserProxy", () => {
  it("splits the authenticated egress proxy URL into server + credentials", () => {
    const proxy = resolveSandboxBrowserProxy({
      HTTPS_PROXY: "https://job-123:hmacsecret@egress.internal:3128",
    });
    expect(proxy).toEqual({
      server: "https://egress.internal:3128",
      username: "job-123",
      password: "hmacsecret",
    });
  });

  it("url-decodes percent-encoded credentials", () => {
    const proxy = resolveSandboxBrowserProxy({
      HTTPS_PROXY: "https://user%40x:p%3Aass@egress.internal:3128",
    });
    expect(proxy?.username).toBe("user@x");
    expect(proxy?.password).toBe("p:ass");
  });

  it("prefers HTTPS_PROXY but falls back through the lowercase/HTTP twins", () => {
    expect(
      resolveSandboxBrowserProxy({ http_proxy: "http://p:q@egress:3128" }),
    ).toEqual({ server: "http://egress:3128", username: "p", password: "q" });
  });

  it("returns undefined outside a proxied sandbox (dev/CLI)", () => {
    expect(resolveSandboxBrowserProxy({})).toBeUndefined();
  });

  it("returns undefined for a malformed proxy value rather than throwing", () => {
    expect(
      resolveSandboxBrowserProxy({ HTTPS_PROXY: "not a url" }),
    ).toBeUndefined();
  });
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

  it("floors the screen at the window without an exact pin", () => {
    // Guard: an exact (min==max) pin wedged the 720p tier in browserforge.
    expect(camoufoxWindowOptions([1280, 720])).toEqual({
      window: [1280, 720],
      screen: { minWidth: 1280, minHeight: 720 },
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

  it("forwards a fixed window and a screen floor when provided", async () => {
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
      screen: { minWidth: 1280, minHeight: 720 },
    });
  });
});
