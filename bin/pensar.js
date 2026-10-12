#!/usr/bin/env node

import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const cliPath = join(__dirname, "..", "build", "cli.js");

// TUI launches, including Herdr restores, need Bun even through the npm shim.
if (typeof globalThis.Bun === "undefined") {
  const args = process.argv.slice(2);
  const commandArgs = args.filter(
    (arg) => !["--obfuscate", "--redact", "-O", "--verbose", "--quiet"].includes(arg),
  );
  for (let i = commandArgs.length - 1; i >= 0; i--) {
    if (commandArgs[i] === "--log-level") {
      const next = commandArgs[i + 1];
      commandArgs.splice(i, next !== undefined && !next.startsWith("-") ? 2 : 1);
    }
  }
  if (commandArgs.length === 0 || commandArgs[0] === "--resume") {
    const { execFileSync } = await import("child_process");
    try {
      execFileSync("bun", [__filename, ...args], { stdio: "inherit" });
      process.exit(0);
    } catch (err) {
      if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
        console.error(
          "TUI mode requires Bun. Install Bun (https://bun.sh) or use a standalone binary release for interactive mode.",
        );
        console.error("All other commands work with Node — run 'pensar --help'.");
        process.exit(1);
      }
      if (err && typeof err === "object" && "status" in err) {
        process.exit(err.status ?? 1);
      }
      process.exit(1);
    }
  }
  process.env.PENSAR_NO_TUI = "1";
}

process.argv = [process.argv[0], cliPath, ...process.argv.slice(2)];
await import(cliPath);
