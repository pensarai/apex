import { describe, it, expect } from "vitest";
import {
  detectPlatform,
  LinuxBackend,
  DarwinBackend,
  WindowsBackend,
} from "./platform";

const BACKEND_METHODS = [
  "screenshot",
  "mouseMove",
  "mouseClick",
  "mouseDoubleClick",
  "typeText",
  "keyPress",
  "getMousePosition",
  "getScreenSize",
  "mouseDrag",
  "scroll",
  "getActiveWindowTitle",
] as const;

describe("Computer Use platform detection", () => {
  it("should detect the current platform", () => {
    const platform = detectPlatform();
    expect(["linux", "darwin", "win32", "unsupported"]).toContain(platform);
  });

  it("should return linux on Linux", () => {
    if (process.platform !== "linux") return;
    expect(detectPlatform()).toBe("linux");
  });

  it("should return darwin on macOS", () => {
    if (process.platform !== "darwin") return;
    expect(detectPlatform()).toBe("darwin");
  });

  it("should return win32 on Windows", () => {
    if (process.platform !== "win32") return;
    expect(detectPlatform()).toBe("win32");
  });
});

describe("LinuxBackend", () => {
  it("should be constructable and implement DesktopBackend", () => {
    const backend = new LinuxBackend();
    expect(backend).toBeDefined();
    for (const method of BACKEND_METHODS) {
      expect(typeof backend[method]).toBe("function");
    }
  });
});

describe("DarwinBackend", () => {
  it("should be constructable and implement DesktopBackend", () => {
    const backend = new DarwinBackend();
    expect(backend).toBeDefined();
    for (const method of BACKEND_METHODS) {
      expect(typeof backend[method]).toBe("function");
    }
  });
});

describe("WindowsBackend", () => {
  it("should be constructable and implement DesktopBackend", () => {
    const backend = new WindowsBackend();
    expect(backend).toBeDefined();
    for (const method of BACKEND_METHODS) {
      expect(typeof backend[method]).toBe("function");
    }
  });
});
