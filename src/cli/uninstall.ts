#!/usr/bin/env bun

/**
 * Pensar Uninstall CLI
 *
 * Fully removes the Pensar installation:
 *   - Removes the pensar binary/package (npm, homebrew, or binary)
 *   - Cleans ~/.pensar/ data directory, preserving sessions, memories, and skills
 *
 * Usage:
 *   pensar uninstall              Uninstall Pensar (interactive confirmation)
 *   pensar uninstall --force      Uninstall without confirmation prompt
 */

import { spawnSync } from "child_process";
import fs from "fs/promises";
import os from "os";
import path from "path";
import * as readline from "readline";
import {
  detectInstallMethod,
  type InstallMethod,
} from "../core/installation/index";

const PRESERVED_DIRS = new Set(["sessions", "memories", "skills"]);

function getPensarDir(): string {
  return process.env.PENSAR_DATA_DIR ?? path.join(os.homedir(), ".pensar");
}

function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function findBinaryPath(): string | null {
  // For compiled binaries, process.execPath IS the pensar binary itself.
  // This is more reliable than `which` when multiple installations coexist.
  const execName =
    process.execPath
      .split("/")
      .pop()
      ?.replace(/\.exe$/, "") ?? "";
  const isCompiledBinary =
    execName !== "bun" && execName !== "node" && execName !== "bun-debug";
  if (isCompiledBinary && require("fs").existsSync(process.execPath)) {
    return process.execPath;
  }

  const result = spawnSync("which", ["pensar"], {
    encoding: "utf-8",
    timeout: 5000,
  });
  if (result.status === 0 && result.stdout) {
    return result.stdout.trim();
  }
  const defaultPath = path.join(os.homedir(), ".local", "bin", "pensar");
  try {
    const stat = require("fs").statSync(defaultPath);
    if (stat) return defaultPath;
  } catch {
    // not found
  }
  return null;
}

function getUninstallDescription(method: InstallMethod): string {
  switch (method) {
    case "npm":
      return "npm uninstall -g @pensar/apex";
    case "homebrew":
      return "brew uninstall pensarai/tap/apex";
    case "binary": {
      const binPath = findBinaryPath();
      return binPath ? `rm ${binPath}` : "remove pensar binary";
    }
  }
}

function removeBinary(method: InstallMethod): {
  success: boolean;
  message: string;
} {
  switch (method) {
    case "npm": {
      const result = spawnSync("npm", ["uninstall", "-g", "@pensar/apex"], {
        encoding: "utf-8",
        timeout: 60000,
        stdio: "pipe",
      });
      return result.status === 0
        ? { success: true, message: "Removed npm package @pensar/apex" }
        : {
            success: false,
            message: `npm uninstall failed: ${result.stderr?.trim() || "unknown error"}`,
          };
    }
    case "homebrew": {
      const result = spawnSync("brew", ["uninstall", "pensarai/tap/apex"], {
        encoding: "utf-8",
        timeout: 60000,
        stdio: "pipe",
      });
      return result.status === 0
        ? {
            success: true,
            message: "Removed Homebrew package pensarai/tap/apex",
          }
        : {
            success: false,
            message: `brew uninstall failed: ${result.stderr?.trim() || "unknown error"}`,
          };
    }
    case "binary": {
      const binPath = findBinaryPath();
      if (!binPath) {
        return {
          success: false,
          message: "Could not locate pensar binary",
        };
      }
      try {
        require("fs").unlinkSync(binPath);
        return { success: true, message: `Removed binary at ${binPath}` };
      } catch (err) {
        return {
          success: false,
          message: `Failed to remove ${binPath}: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }
  }
}

async function cleanDataDir(): Promise<{
  removed: string[];
  preserved: string[];
  errors: string[];
}> {
  const pensarDir = getPensarDir();
  const removed: string[] = [];
  const preserved: string[] = [];
  const errors: string[] = [];

  const dirExists = await fs
    .access(pensarDir)
    .then(() => true)
    .catch(() => false);

  if (!dirExists) {
    return { removed, preserved, errors };
  }

  let entries: string[];
  try {
    entries = await fs.readdir(pensarDir);
  } catch {
    errors.push(`Could not read ${pensarDir}`);
    return { removed, preserved, errors };
  }

  for (const name of entries) {
    if (PRESERVED_DIRS.has(name)) {
      preserved.push(name);
      continue;
    }

    const target = path.join(pensarDir, name);
    try {
      const stat = await fs.lstat(target);
      if (stat.isDirectory()) {
        await fs.rm(target, { recursive: true, force: true });
      } else {
        await fs.unlink(target);
      }
      removed.push(name);
    } catch (err) {
      errors.push(
        `Failed to remove ${name}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  return { removed, preserved, errors };
}

async function uninstall(force: boolean): Promise<void> {
  const method = detectInstallMethod();
  const pensarDir = getPensarDir();

  process.stdout.write(`Pensar Uninstall

  Install method:  ${method}
  Binary removal:  ${getUninstallDescription(method)}
  Data directory:  ${pensarDir}

  Preserved data:  sessions, memories, skills
`);

  if (!force) {
    const answer = await prompt("Proceed with uninstall? (y/N): ");
    if (answer.toLowerCase() !== "y") {
      process.stdout.write("Aborted.\n");
      return;
    }
    process.stdout.write("\n");
  }

  // 1. Clean data directory
  process.stdout.write("Cleaning data directory...\n");
  const { removed, preserved, errors } = await cleanDataDir();

  for (const name of removed) {
    process.stdout.write(`  Removed ${name}\n`);
  }
  for (const name of preserved) {
    process.stdout.write(`  Preserved ${name}/\n`);
  }
  for (const msg of errors) {
    process.stderr.write(`  ${msg}\n`);
  }

  if (removed.length === 0 && errors.length === 0) {
    process.stdout.write("  Nothing to clean.\n");
  }

  // 2. Remove binary/package
  process.stdout.write("\n");
  process.stdout.write("Removing pensar...\n");
  const result = removeBinary(method);

  if (result.success) {
    process.stdout.write(`  ${result.message}\n`);
  } else {
    process.stderr.write(`  ${result.message}\n`);
  }

  // 3. Summary
  process.stdout.write("\n");
  if (result.success && errors.length === 0) {
    process.stdout.write("✓ Pensar has been uninstalled.\n");
  } else {
    process.stdout.write("⚠ Uninstall completed with warnings (see above).\n");
  }

  if (preserved.length > 0) {
    process.stdout.write(
      `  Preserved data remains at ${pensarDir}/ (${preserved.join(", ")})\n`,
    );
    process.stdout.write("  To remove all data: rm -rf ~/.pensar\n");
  }

  if (method === "binary") {
    process.stdout.write(
      "\n  Note: You may want to remove the PATH export from your shell config\n  (~/.bashrc, ~/.zshrc, etc.) if it was added during install.\n",
    );
  }
}

function showHelp(): void {
  process.stdout.write(`Pensar Uninstall — Remove Pensar from your system

Usage:
  pensar uninstall             Uninstall Pensar (keeps sessions, memories, skills)
  pensar uninstall --force     Skip confirmation prompt

Options:
  --force, -f          Skip confirmation prompt
  -h, --help           Show this help message\n`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const subcommand = args[0];

  if (subcommand === "help" || subcommand === "--help" || subcommand === "-h") {
    showHelp();
    return;
  }

  const force = args.includes("--force") || args.includes("-f");

  try {
    await uninstall(force);
  } catch (err) {
    process.stderr.write(
      `\nError: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
}

main();
