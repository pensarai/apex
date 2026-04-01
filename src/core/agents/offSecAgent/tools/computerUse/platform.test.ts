import { describe, it, expect } from "vitest";
import { detectPlatform, LinuxBackend, DarwinBackend } from "./platform";

describe("Computer Use platform detection", () => {
  it("should detect the current platform", () => {
    const platform = detectPlatform();
    expect(["linux", "darwin", "unsupported"]).toContain(platform);
  });

  it("should return linux on Linux", () => {
    if (process.platform !== "linux") return;
    expect(detectPlatform()).toBe("linux");
  });

  it("should return darwin on macOS", () => {
    if (process.platform !== "darwin") return;
    expect(detectPlatform()).toBe("darwin");
  });
});

describe("LinuxBackend", () => {
  it("should be constructable", () => {
    const backend = new LinuxBackend();
    expect(backend).toBeDefined();
    expect(typeof backend.screenshot).toBe("function");
    expect(typeof backend.mouseMove).toBe("function");
    expect(typeof backend.mouseClick).toBe("function");
    expect(typeof backend.mouseDoubleClick).toBe("function");
    expect(typeof backend.typeText).toBe("function");
    expect(typeof backend.keyPress).toBe("function");
    expect(typeof backend.getMousePosition).toBe("function");
    expect(typeof backend.getScreenSize).toBe("function");
    expect(typeof backend.mouseDrag).toBe("function");
    expect(typeof backend.scroll).toBe("function");
    expect(typeof backend.getActiveWindowTitle).toBe("function");
  });
});

describe("DarwinBackend", () => {
  it("should be constructable", () => {
    const backend = new DarwinBackend();
    expect(backend).toBeDefined();
    expect(typeof backend.screenshot).toBe("function");
    expect(typeof backend.mouseMove).toBe("function");
    expect(typeof backend.mouseClick).toBe("function");
    expect(typeof backend.mouseDoubleClick).toBe("function");
    expect(typeof backend.typeText).toBe("function");
    expect(typeof backend.keyPress).toBe("function");
    expect(typeof backend.getMousePosition).toBe("function");
    expect(typeof backend.getScreenSize).toBe("function");
    expect(typeof backend.mouseDrag).toBe("function");
    expect(typeof backend.scroll).toBe("function");
    expect(typeof backend.getActiveWindowTitle).toBe("function");
  });
});
