import { exec } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  keyPressCommand,
  launchCommand,
  mouseClickCommand,
  mouseDoubleClickCommand,
  mouseDragCommand,
  mouseMoveCommand,
  readinessProbe,
  screenInfoCommand,
  screenshotCommand,
  scrollCommand,
  shellRun,
  typeTextCommand,
} from "./commands";
import type { BuildManifest } from "./types";

// Decode a Windows `-EncodedCommand` payload back to the PowerShell source so
// tests can assert on the script the sandbox will actually run.
function decodeWindows(cmd: string): string {
  const marker = "-EncodedCommand ";
  const idx = cmd.indexOf(marker);
  if (idx === -1) throw new Error(`not an -EncodedCommand string: ${cmd}`);
  const b64 = cmd.slice(idx + marker.length).trim();
  return Buffer.from(b64, "base64").toString("utf16le");
}

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

  it("skips env entries whose value is not a string", () => {
    // Manifests are parsed JSON — a null/numeric value must not reach quoting.
    const withNull = {
      ...launch,
      environment: [
        { name: "NULLED", value: null },
        { name: "LOG", value: "debug" },
      ] as unknown as BuildManifest["launch"]["environment"],
    };
    expect(() => launchCommand("linux", withNull)).not.toThrow();
    expect(launchCommand("linux", withNull)).not.toContain("NULLED");
    expect(launchCommand("linux", withNull)).toContain("LOG=");
    expect(launchCommand("windows", withNull)).not.toContain("NULLED");
  });

  it("throws without an executablePath", () => {
    expect(() =>
      launchCommand("linux", { ...launch, executablePath: null }),
    ).toThrow(/executablePath is required/);
  });

  it.skipIf(process.platform === "win32")(
    "returns to the executor without waiting for the app to exit",
    async () => {
      // Regression: `cd X && app >log &` backgrounds a subshell that keeps the
      // executor's stdout/stderr pipes open, so the launch step blocked until
      // the app exited — i.e. forever, for a real desktop app.
      const dir = await mkdtemp(join(tmpdir(), "pensar-launch-"));
      const script = join(dir, "app.sh");
      await writeFile(script, "#!/usr/bin/env bash\nsleep 5\n", {
        mode: 0o755,
      });

      const started = Date.now();
      await new Promise<void>((resolve, reject) => {
        exec(
          launchCommand("linux", {
            executablePath: script,
            args: [],
            workingDirectory: dir,
            environment: [],
          }),
          (err) => (err ? reject(err) : resolve()),
        );
      });
      expect(Date.now() - started).toBeLessThan(3000);
    },
  );
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
    ).toContain("Get-CimInstance Win32_Process");
  });

  it("matches the windows process probe against the command line", () => {
    // pgrep -f accepts a path fragment; the windows probe must too, so it
    // checks CommandLine (not just the bare image name).
    const probe = readinessProbe("windows", {
      kind: "process",
      process: "C:\\Program Files\\App\\app.exe --headless",
    });
    expect(probe).toContain("$_.CommandLine -like");
    expect(probe).toContain("$_.Name -like");
    expect(probe).toContain("app.exe --headless");
  });

  it("escapes -like wildcards in windows patterns", () => {
    expect(
      readinessProbe("windows", { kind: "process", process: "a[p]p*" }),
    ).toContain("*a`[p`]p`**");
    expect(
      readinessProbe("windows", {
        kind: "window-title",
        titleContains: "Save?",
      }),
    ).toContain("*Save`?*");
  });

  it("builds port probes per OS", () => {
    const linux = readinessProbe("linux", { kind: "port", port: 8080 });
    expect(linux).toContain(":8080");
    // ss is missing on minimal images, so the probe must have a fallback.
    expect(linux).toContain("/dev/tcp/127.0.0.1/8080");
    expect(readinessProbe("macos", { kind: "port", port: 8080 })).toContain(
      "lsof",
    );
    expect(readinessProbe("windows", { kind: "port", port: 8080 })).toContain(
      "Get-NetTCPConnection",
    );
  });
});

describe("screenshotCommand", () => {
  it("captures via scrot with an ImageMagick fallback on linux", () => {
    const cmd = screenshotCommand("linux", "/tmp/shot.png");
    expect(cmd).toContain("scrot -o");
    expect(cmd).toContain("import -window root");
    expect(cmd).toContain("/tmp/shot.png");
  });

  it("uses screencapture on macos", () => {
    expect(screenshotCommand("macos", "/tmp/shot.png")).toContain(
      "screencapture -x",
    );
  });

  it("uses .NET Graphics.CopyFromScreen on windows", () => {
    const script = decodeWindows(screenshotCommand("windows", "C:/shot.png"));
    expect(script).toContain("System.Drawing.Graphics");
    expect(script).toContain("CopyFromScreen");
    expect(script).toContain("C:/shot.png");
  });
});

describe("mouseMoveCommand", () => {
  it("builds per-OS move commands", () => {
    expect(mouseMoveCommand("linux", 10, 20)).toBe("xdotool mousemove 10 20");
    expect(mouseMoveCommand("macos", 10, 20)).toBe("cliclick m:10,20");
    expect(decodeWindows(mouseMoveCommand("windows", 10, 20))).toContain(
      "[PensarWin32]::SetCursorPos(10, 20)",
    );
  });
});

describe("mouseClickCommand", () => {
  it("moves then clicks the mapped button on linux", () => {
    expect(mouseClickCommand("linux", "left", 5, 6)).toBe(
      "xdotool mousemove 5 6 click 1",
    );
    expect(mouseClickCommand("linux", "right", 5, 6)).toContain("click 3");
    expect(mouseClickCommand("linux", "middle", 5, 6)).toContain("click 2");
  });

  it("uses cliclick c/rc on macos (middle falls back to left)", () => {
    expect(mouseClickCommand("macos", "left", 5, 6)).toBe("cliclick c:5,6");
    expect(mouseClickCommand("macos", "right", 5, 6)).toBe("cliclick rc:5,6");
    expect(mouseClickCommand("macos", "middle", 5, 6)).toBe("cliclick c:5,6");
  });

  it("uses user32 mouse_event on windows", () => {
    const script = decodeWindows(mouseClickCommand("windows", "right", 5, 6));
    expect(script).toContain("user32.dll");
    expect(script).toContain("[PensarWin32]::SetCursorPos(5, 6)");
    expect(script).toContain("[PensarWin32]::RIGHTDOWN");
    expect(script).toContain("mouse_event");
  });
});

describe("mouseDoubleClickCommand", () => {
  it("builds per-OS double-click commands", () => {
    expect(mouseDoubleClickCommand("linux", 1, 2)).toContain(
      "click --repeat 2",
    );
    expect(mouseDoubleClickCommand("macos", 1, 2)).toBe("cliclick dc:1,2");
    expect(decodeWindows(mouseDoubleClickCommand("windows", 1, 2))).toContain(
      "mouse_event",
    );
  });
});

describe("mouseDragCommand", () => {
  it("builds press-move-release drags per OS", () => {
    expect(mouseDragCommand("linux", 1, 2, 3, 4)).toBe(
      "xdotool mousemove 1 2 mousedown 1 mousemove 3 4 mouseup 1",
    );
    expect(mouseDragCommand("macos", 1, 2, 3, 4)).toBe(
      "cliclick dd:1,2 du:3,4",
    );
    const script = decodeWindows(mouseDragCommand("windows", 1, 2, 3, 4));
    expect(script).toContain("[PensarWin32]::SetCursorPos(1, 2)");
    expect(script).toContain("[PensarWin32]::SetCursorPos(3, 4)");
    expect(script).toContain("LEFTUP");
  });
});

describe("typeTextCommand", () => {
  it("types literal text per OS", () => {
    expect(typeTextCommand("linux", "hi there")).toContain(
      "xdotool type --clearmodifiers --",
    );
    expect(typeTextCommand("linux", "hi there")).toContain("hi there");
    expect(typeTextCommand("macos", "hi there")).toContain("cliclick");
    expect(typeTextCommand("macos", "hi there")).toContain("t:hi there");
    expect(decodeWindows(typeTextCommand("windows", "hi there"))).toContain(
      "SendKeys",
    );
  });

  it("escapes SendKeys control chars on windows", () => {
    const script = decodeWindows(typeTextCommand("windows", "a+b(c)"));
    expect(script).toContain("a{+}b{(}c{)}");
  });
});

describe("keyPressCommand", () => {
  it("passes combos straight through to xdotool on linux", () => {
    expect(keyPressCommand("linux", "ctrl+c")).toContain(
      "xdotool key --clearmodifiers",
    );
    expect(keyPressCommand("linux", "ctrl+c")).toContain("ctrl+c");
  });

  it("expands combos into cliclick kd/kp/ku on macos", () => {
    const cmd = keyPressCommand("macos", "ctrl+c");
    expect(cmd).toContain("cliclick");
    expect(cmd).toContain("kd:ctrl");
    expect(cmd).toContain("kp:c");
    expect(cmd).toContain("ku:ctrl");
    // Named single keys map to cliclick's vocabulary.
    expect(keyPressCommand("macos", "Return")).toContain("kp:return");
  });

  it("maps combos to SendKeys notation on windows", () => {
    expect(decodeWindows(keyPressCommand("windows", "ctrl+c"))).toContain(
      "SendKeys",
    );
    expect(decodeWindows(keyPressCommand("windows", "ctrl+c"))).toContain(
      "SendWait('^c')",
    );
    expect(decodeWindows(keyPressCommand("windows", "alt+Tab"))).toContain(
      "SendWait('%{TAB}')",
    );
  });

  it("maps function keys per backend", () => {
    expect(keyPressCommand("macos", "alt+F4")).toContain("kp:f4");
    expect(keyPressCommand("macos", "F12")).toContain("kp:f12");
    expect(decodeWindows(keyPressCommand("windows", "alt+F4"))).toContain(
      "SendWait('%{F4}')",
    );
    expect(decodeWindows(keyPressCommand("windows", "F12"))).toContain(
      "SendWait('{F12}')",
    );
  });
});

describe("scrollCommand", () => {
  it("scrolls with xdotool wheel buttons on linux", () => {
    expect(scrollCommand("linux", 3)).toContain("click --repeat 3");
    expect(scrollCommand("linux", 3)).toContain("50 5"); // down = button 5
    expect(scrollCommand("linux", -2)).toContain("50 4"); // up = button 4
    expect(scrollCommand("linux", 1, 10, 20)).toContain("mousemove 10 20");
  });

  it("approximates scroll with arrow keys on macos", () => {
    expect(scrollCommand("macos", 2)).toContain("kp:arrow-down");
    expect(scrollCommand("macos", -2)).toContain("kp:arrow-up");
    expect(scrollCommand("macos", 1, 10, 20)).toContain("m:10,20");
  });

  it("uses the mouse wheel event on windows", () => {
    const down = decodeWindows(scrollCommand("windows", 2));
    expect(down).toContain("[PensarWin32]::WHEEL");
    expect(down).toContain("-120"); // negative delta = scroll down
    expect(decodeWindows(scrollCommand("windows", -1))).toContain(", 120,");
  });
});

describe("screenInfoCommand", () => {
  it("reads geometry, mouse position, and active window on linux", () => {
    const cmd = screenInfoCommand("linux");
    expect(cmd).toContain("xdotool getdisplaygeometry");
    expect(cmd).toContain("getmouselocation --shell");
    expect(cmd).toContain("getactivewindow getwindowname");
    expect(cmd).toContain("SIZE=");
  });

  it("uses osascript + cliclick on macos", () => {
    const cmd = screenInfoCommand("macos");
    expect(cmd).toContain("osascript");
    expect(cmd).toContain("NSScreen");
    expect(cmd).toContain("cliclick p");
  });

  it("uses SystemInformation + user32 on windows", () => {
    const script = decodeWindows(screenInfoCommand("windows"));
    expect(script).toContain("System.Windows.Forms.SystemInformation");
    expect(script).toContain("GetForegroundWindow");
    expect(script).toContain("GetCursorPos");
  });
});
