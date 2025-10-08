#!/usr/bin/env bun
import { watch } from "fs";
import { spawn, type Subprocess } from "bun";
import { resolve, join } from "path";

const TARGET_FILE = "src/index.tsx";
const WATCH_DIRS = ["src"];

let currentProcess: Subprocess | null = null;

function clearTerminal() {
  // Clear screen and reset cursor
  process.stdout.write("\x1b[2J\x1b[H");
  console.log("\x1b[36m[watch]\x1b[0m Restarting due to changes...\n");
}

async function startApp() {
  // Kill existing process if running
  if (currentProcess) {
    try {
      currentProcess.kill();
      await new Promise((resolve) => setTimeout(resolve, 100));
    } catch (e) {
      // Process already dead
    }
  }

  clearTerminal();

  // Start new process
  currentProcess = spawn({
    cmd: ["bun", "run", TARGET_FILE],
    stdout: "inherit",
    stderr: "inherit",
    stdin: "inherit",
  });

  currentProcess.exited.then((code) => {
    if (code !== null && code !== 0 && code !== 130) {
      // 130 is Ctrl+C
      console.error(`\x1b[31m[watch]\x1b[0m Process exited with code ${code}`);
    }
  });
}

// Watch for file changes
console.log("\x1b[36m[watch]\x1b[0m Starting file watcher...");
console.log(`\x1b[36m[watch]\x1b[0m Watching: ${WATCH_DIRS.join(", ")}\n`);

// Initial start
startApp();

// Set up watchers for each directory
let debounceTimer: Timer | null = null;

for (const dir of WATCH_DIRS) {
  const watchPath = resolve(process.cwd(), dir);

  const watcher = watch(
    watchPath,
    { recursive: true },
    (eventType, filename) => {
      if (!filename) return;

      // Ignore non-source files
      if (
        !filename.endsWith(".tsx") &&
        !filename.endsWith(".ts") &&
        !filename.endsWith(".jsx") &&
        !filename.endsWith(".js")
      ) {
        return;
      }

      // Debounce rapid changes
      if (debounceTimer) {
        clearTimeout(debounceTimer);
      }

      debounceTimer = setTimeout(() => {
        console.log(`\x1b[36m[watch]\x1b[0m File changed: ${filename}`);
        startApp();
      }, 100);
    }
  );
}

// Handle Ctrl+C gracefully
process.on("SIGINT", () => {
  console.log("\n\x1b[36m[watch]\x1b[0m Shutting down...");
  if (currentProcess) {
    currentProcess.kill();
  }
  process.exit(0);
});
