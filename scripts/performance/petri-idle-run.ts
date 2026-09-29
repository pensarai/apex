#!/usr/bin/env bun

// Runs the real TUI entry in this process while sampling process.cpuUsage
// for the PTY driver's phase report. Each sample records its actual interval
// start/end wall-clock stamps and monotonic wall duration, so the driver can
// attribute whole intervals to phases without assuming the nominal 250 ms
// period. The CPU baseline is one absolute snapshot taken before the log
// write and retained for the next interval, so each interval's CPU covers
// exactly its wall window and the write's own cost lands in the next
// interval instead of being excluded. The driver owns focus/blur/refocus/
// resize/typing phases and measures renderer output on the PTY side.
//
// Usage (from the driver):
//   PETRI_IDLE_LOG=<path> bun --no-env-file scripts/performance/petri-idle-run.ts

import { appendFileSync } from "node:fs";

const logPath = process.env.PETRI_IDLE_LOG;
if (!logPath) throw new Error("PETRI_IDLE_LOG must name the sample log");

let lastMonotonic = performance.now();
let lastWallClock = Date.now();
let lastCpu = process.cpuUsage();
setInterval(() => {
  const monotonic = performance.now();
  const wallClock = Date.now();
  const currentCpu = process.cpuUsage();
  appendFileSync(
    logPath,
    `${JSON.stringify({
      startT: lastWallClock,
      endT: wallClock,
      wallMs: monotonic - lastMonotonic,
      cpuUs:
        currentCpu.user - lastCpu.user + (currentCpu.system - lastCpu.system),
    })}\n`,
  );
  lastMonotonic = monotonic;
  lastWallClock = wallClock;
  lastCpu = currentCpu;
}, 250);

await import("../../src/tui/index.tsx");
