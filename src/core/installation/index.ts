import { spawnSync } from "child_process";
import packageJson from "../../../package.json";

export type InstallMethod = "npm" | "homebrew" | "binary";

export interface UpgradeResult {
  success: boolean;
  message: string;
  fromVersion: string;
  toVersion: string;
}

export namespace Installation {
  export async function getVersion() {
    if (process.env["APEX_VERSION"]) return process.env["APEX_VERSION"];

    const version = await fetch(
      "https://registry.npmjs.org/@pensar/apex/latest",
    ).then(async (res) => {
      if (!res.ok) throw new Error(res.statusText);
      const data = (await res.json()) as Record<string, unknown>;
      return String(data.version);
    });
    return version;
  }

  export function getCurrentVersion(): string {
    return packageJson.version;
  }

  export async function getLatestVersion(): Promise<string> {
    const res = await fetch(
      "https://registry.npmjs.org/@pensar/apex/latest",
    );
    if (!res.ok) throw new Error(`Failed to fetch latest version: ${res.statusText}`);
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

    const npmCheck = spawnSync("npm", ["list", "-g", "@pensar/apex", "--depth=0"], {
      encoding: "utf-8",
      timeout: 10000,
    });
    if (npmCheck.status === 0 && npmCheck.stdout?.includes("@pensar/apex")) {
      return "npm";
    }

    return "binary";
  }

  function getUpgradeCommand(method: InstallMethod): { cmd: string; args: string[] } {
    switch (method) {
      case "npm":
        return { cmd: "npm", args: ["install", "-g", "@pensar/apex@latest"] };
      case "homebrew":
        return { cmd: "brew", args: ["upgrade", "pensarai/apex/apex"] };
      case "binary":
        return { cmd: "bash", args: ["-c", "curl -fsSL https://pensarai.com/install.sh | bash"] };
    }
  }

  export function getUpgradeCommandString(method: InstallMethod): string {
    const { cmd, args } = getUpgradeCommand(method);
    return `${cmd} ${args.join(" ")}`;
  }

  export function runUpgrade(method: InstallMethod): UpgradeResult {
    const currentVersion = getCurrentVersion();
    const { cmd, args } = getUpgradeCommand(method);

    const result = spawnSync(cmd, args, {
      encoding: "utf-8",
      timeout: 120000,
      stdio: "pipe",
    });

    if (result.status !== 0) {
      const stderr = result.stderr?.trim() || "Unknown error";
      return {
        success: false,
        message: `Upgrade failed: ${stderr}`,
        fromVersion: currentVersion,
        toVersion: currentVersion,
      };
    }

    return {
      success: true,
      message: "Upgrade successful. Please restart pensar to use the new version.",
      fromVersion: currentVersion,
      toVersion: "latest",
    };
  }

  export async function upgrade(): Promise<UpgradeResult> {
    const currentVersion = getCurrentVersion();
    let latestVersion: string;

    try {
      latestVersion = await getLatestVersion();
    } catch {
      return {
        success: false,
        message: "Failed to check for updates. Please check your internet connection.",
        fromVersion: currentVersion,
        toVersion: currentVersion,
      };
    }

    if (currentVersion === latestVersion) {
      return {
        success: true,
        message: `Already on the latest version (v${currentVersion}).`,
        fromVersion: currentVersion,
        toVersion: latestVersion,
      };
    }

    const method = detectInstallMethod();
    const result = runUpgrade(method);

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
}
