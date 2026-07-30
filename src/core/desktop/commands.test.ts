import { exec } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { launchCommand, readinessProbe, shellRun } from "./commands";
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
