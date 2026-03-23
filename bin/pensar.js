#!/usr/bin/env node

import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const cliPath = join(__dirname, "..", "build", "cli.js");

// Under Node, try to re-exec under Bun if no subcommand given (TUI needs Bun)
if (typeof globalThis.Bun === "undefined") {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    // No subcommand = TUI mode — try re-exec under Bun
    const { execFileSync } = await import("child_process");
    try {
      execFileSync("bun", [__filename], { stdio: "inherit" });
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
