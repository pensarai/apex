import { spawnSync } from "node:child_process";
import packageJson from "../../../package.json";

export type InstallMethod = "npm" | "homebrew" | "binary";

export interface UpgradeResult {
  success: boolean;
  message: string;
  fromVersion: string;
  toVersion: string;
}

export async function resolveVersion(): Promise<string> {
  if (process.env["APEX_VERSION"]) return process.env["APEX_VERSION"];
  return getLatestVersion();
}

export function getCurrentVersion(): string {
  return packageJson.version;
}

/**
 * Returns true if `latest` is strictly greater than `current` by semver.
 * Only compares major.minor.patch; pre-release suffixes are ignored.
 */
export function isNewerVersion(current: string, latest: string): boolean {
  const parse = (v: string) => v.split(".").map((n) => parseInt(n, 10) || 0);
  const c = parse(current);
  const l = parse(latest);
  for (let i = 0; i < Math.max(c.length, l.length); i++) {
    const cv = c[i] ?? 0;
    const lv = l[i] ?? 0;
    if (lv > cv) return true;
    if (lv < cv) return false;
  }
  return false;
}

export async function getLatestVersion(): Promise<string> {
  const res = await fetch("https://registry.npmjs.org/@pensar/apex/latest");
  if (!res.ok)
    throw new Error(`Failed to fetch latest version: ${res.statusText}`);
  const data = (await res.json()) as Record<string, unknown>;
  return String(data.version);
}

export function detectInstallMethod(): InstallMethod {
  const execPath = process.execPath;
  const argv1 = process.argv[1] ?? "";

  if (
    execPath.includes("homebrew") ||
    execPath.includes("Cellar") ||
    execPath.includes("linuxbrew") ||
    argv1.includes("homebrew") ||
    argv1.includes("Cellar")
  ) {
    return "homebrew";
  }

  if (
    argv1.includes("node_modules") ||
    argv1.includes(".npm") ||
    argv1.includes("npx")
  ) {
    return "npm";
  }

  // Determine if we're running as a compiled binary vs via an interpreter.
  // Compiled Bun binaries have process.execPath pointing to the binary itself
  // (e.g. ~/.local/bin/pensar), while interpreted scripts have it pointing to
  // the runtime (e.g. ~/.bun/bin/bun or /usr/local/bin/node).
  const execName =
    execPath
      .split("/")
      .pop()
      ?.replace(/\.exe$/, "") ?? "";
  const isInterpreter =
    execName === "bun" || execName === "node" || execName === "bun-debug";

  if (!isInterpreter) {
    return "binary";
  }

  const npmCheck = spawnSync(
    "npm",
    ["list", "-g", "@pensar/apex", "--depth=0"],
    {
      encoding: "utf-8",
      timeout: 10000,
    },
  );
  if (npmCheck.status === 0 && npmCheck.stdout?.includes("@pensar/apex")) {
    return "npm";
  }

  return "binary";
}

function getUpgradeCommand(method: InstallMethod): {
  cmd: string;
  args: string[];
} {
  switch (method) {
    case "npm":
      return { cmd: "npm", args: ["install", "-g", "@pensar/apex@latest"] };
    case "homebrew":
      return { cmd: "brew", args: ["upgrade", "pensarai/tap/apex"] };
    case "binary":
      return {
        cmd: "bash",
        args: ["-c", "curl -fsSL https://pensarai.com/install.sh | bash"],
      };
  }
}

export function getUpgradeCommandString(method: InstallMethod): string {
  const { cmd, args } = getUpgradeCommand(method);
  return `${cmd} ${args.join(" ")}`;
}

export interface CheckUpdateResult {
  updateAvailable: boolean;
  currentVersion: string;
  latestVersion: string;
}

export async function checkForUpdate(): Promise<CheckUpdateResult> {
  const currentVersion = getCurrentVersion();
  let latestVersion: string;

  try {
    latestVersion = await getLatestVersion();
  } catch {
    return {
      updateAvailable: false,
      currentVersion,
      latestVersion: currentVersion,
    };
  }

  return {
    updateAvailable: isNewerVersion(currentVersion, latestVersion),
    currentVersion,
    latestVersion,
  };
}

function runUpgrade(
  method: InstallMethod,
  options?: { interactive?: boolean },
): UpgradeResult {
  const currentVersion = getCurrentVersion();
  const { cmd, args } = getUpgradeCommand(method);
  const interactive = options?.interactive ?? false;

  const result = spawnSync(cmd, args, {
    encoding: "utf-8",
    timeout: 120000,
    stdio: interactive ? "inherit" : "pipe",
  });

  if (result.status !== 0) {
    const stderr =
      (typeof result.stderr === "string" ? result.stderr.trim() : "") ||
      "Unknown error";
    return {
      success: false,
      message: `Upgrade failed: ${stderr}`,
      fromVersion: currentVersion,
      toVersion: currentVersion,
    };
  }

  return {
    success: true,
    message:
      "Upgrade successful. Please restart pensar to use the new version.",
    fromVersion: currentVersion,
    toVersion: "latest",
  };
}

export async function upgrade(options?: {
  interactive?: boolean;
}): Promise<UpgradeResult> {
  const currentVersion = getCurrentVersion();
  let latestVersion: string;

  try {
    latestVersion = await getLatestVersion();
  } catch {
    return {
      success: false,
      message:
        "Failed to check for updates. Please check your internet connection.",
      fromVersion: currentVersion,
      toVersion: currentVersion,
    };
  }

  if (!isNewerVersion(currentVersion, latestVersion)) {
    return {
      success: true,
      message: `Already on the latest version (v${currentVersion}).`,
      fromVersion: currentVersion,
      toVersion: latestVersion,
    };
  }

  const method = detectInstallMethod();
  const result = runUpgrade(method, options);

  if (result.success) {
    return {
      ...result,
      toVersion: latestVersion,
      message: `Upgraded from v${currentVersion} to v${latestVersion}. Please restart pensar.`,
    };
  }

  return {
    ...result,
    toVersion: latestVersion,
    message: `${result.message}\n\nYou can upgrade manually by running:\n  ${getUpgradeCommandString(method)}`,
  };
}
