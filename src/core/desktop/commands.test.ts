import { describe, expect, it } from "vitest";
import {
  launchCommand,
  readinessProbe,
  screenshotCommand,
  shellRun,
} from "./commands";
import type { BuildManifest } from "./types";

describe("shellRun", () => {
  it("wraps linux/macos scripts in bash", () => {
    expect(shellRun("linux", "echo hi")).toBe("bash -lc 'echo hi'");
    expect(shellRun("macos", "echo hi")).toBe("bash -lc 'echo hi'");
  });

  it("wraps windows scripts in PowerShell", () => {
    expect(shellRun("windows", "Write-Host hi")).toBe(
      "powershell -NoProfile -NonInteractive -Command 'Write-Host hi'",
    );
  });

  it("escapes embedded single quotes per shell", () => {
    expect(shellRun("linux", "echo 'x'")).toContain(`'\\''`);
    expect(shellRun("windows", "echo 'x'")).toContain("''");
  });
});

const launch: BuildManifest["launch"] = {
  executablePath: "/opt/app/app",
  args: ["--headless", "--port=9000"],
  workingDirectory: "/opt/app",
  environment: [
    { name: "LOG", value: "debug" },
    { name: "TOKEN", secretRef: "cred-1" },
  ],
};

describe("launchCommand", () => {
  it("backgrounds the app with env + cwd on linux", () => {
    const cmd = launchCommand("linux", launch);
    expect(cmd).toContain("cd ");
    expect(cmd).toContain("/opt/app");
    expect(cmd).toContain("LOG=");
    expect(cmd).toContain("--headless");
    expect(cmd).toContain("&"); // backgrounded
    // secretRef-only env (no value) is not inlined
    expect(cmd).not.toContain("TOKEN=");
  });

  it("uses Start-Process on windows", () => {
    const cmd = launchCommand("windows", launch);
    expect(cmd).toContain("Start-Process");
    expect(cmd).toContain("-ArgumentList");
    expect(cmd).toContain("$env:LOG=");
  });

  it("throws without an executablePath", () => {
    expect(() =>
      launchCommand("linux", { ...launch, executablePath: null }),
    ).toThrow(/executablePath is required/);
  });
});

describe("readinessProbe", () => {
  it("returns null for sleep (runner waits instead)", () => {
    expect(readinessProbe("linux", { kind: "sleep", seconds: 3 })).toBeNull();
  });

  it("builds process probes per OS", () => {
    expect(
      readinessProbe("linux", { kind: "process", process: "app" }),
    ).toContain("pgrep");
    expect(
      readinessProbe("windows", { kind: "process", process: "app" }),
    ).toContain("Get-Process");
  });

  it("builds port probes per OS", () => {
    expect(readinessProbe("linux", { kind: "port", port: 8080 })).toContain(
      ":8080",
    );
    expect(readinessProbe("macos", { kind: "port", port: 8080 })).toContain(
      "lsof",
    );
    expect(readinessProbe("windows", { kind: "port", port: 8080 })).toContain(
      "Get-NetTCPConnection",
    );
  });
});

describe("screenshotCommand", () => {
  it("uses the OS-native capture tool", () => {
    expect(screenshotCommand("macos", "/tmp/s.png")).toContain("screencapture");
    expect(screenshotCommand("windows", "/tmp/s.png")).toContain(
      "CopyFromScreen",
    );
    expect(screenshotCommand("linux", "/tmp/s.png")).toContain("scrot");
  });
});
