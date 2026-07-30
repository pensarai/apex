import { describe, expect, it } from "vitest";
import { resolveDesktopOs } from "./runtime";

describe("resolveDesktopOs", () => {
  it("maps node platforms to desktop OS names", () => {
    expect(resolveDesktopOs("linux")).toBe("linux");
    expect(resolveDesktopOs("darwin")).toBe("macos");
    expect(resolveDesktopOs("win32")).toBe("windows");
  });

  it("throws on an unsupported platform", () => {
    expect(() => resolveDesktopOs("aix" as NodeJS.Platform)).toThrow(
      /not supported on platform/,
    );
  });

  it("defaults to the current process platform", () => {
    // Whatever host runs the suite, the default must resolve without throwing
    // on the three supported OSes (and throw otherwise — covered above).
    const supported = ["linux", "darwin", "win32"];
    if (supported.includes(process.platform)) {
      expect(() => resolveDesktopOs()).not.toThrow();
    }
  });
});
