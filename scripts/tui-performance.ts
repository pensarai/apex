import { mkdtemp, rm } from "node:fs/promises";
import { cpus, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import reactPackage from "react/package.json";
import type { runTypingJourney } from "./tui-performance/journey";
import type { runScrollingJourney } from "./tui-performance/scrolling";

const runs = Number(process.argv[2] ?? 5);
const journey = process.argv[4] ?? "typing";
if (
  !Number.isSafeInteger(runs) ||
  runs < 1 ||
  runs > 30 ||
  !["typing", "scrolling", "scrolling-idle"].includes(journey)
) {
  throw new Error(
    "Usage: bun run perf:tui [runs: 1..30] [report.json] [typing|scrolling|scrolling-idle]",
  );
}
const scrolling = journey !== "typing";
const streamIntervals = journey === "scrolling-idle" ? [0] : [0, 4];
const corePackage = await Bun.file(
  join(
    dirname(Bun.resolveSync("@opentui/core", import.meta.dir)),
    "package.json",
  ),
).json();
const home = await mkdtemp(join(tmpdir(), "apex-tui-perf-"));
const results: ((
  | Awaited<ReturnType<typeof runTypingJourney>>
  | Awaited<ReturnType<typeof runScrollingJourney>>
) & {
  run: number;
})[] = [];
try {
  for (let run = 0; run < runs; run++) {
    for (const historySize of [100, 1000]) {
      for (const streamEvery of streamIntervals) {
        const child = Bun.spawn(
          [
            process.execPath,
            "--no-env-file",
            join(
              import.meta.dir,
              scrolling
                ? "tui-performance/scrolling.tsx"
                : "tui-performance/journey.tsx",
            ),
            String(historySize),
            String(streamEvery),
          ],
          {
            env: {
              HOME: home,
              PATH: process.env.PATH,
              TERM: "xterm-256color",
              LANG: "en_US.UTF-8",
            },
            stdout: "pipe",
            stderr: "pipe",
            timeout: 30_000,
            killSignal: "SIGKILL",
          },
        );
        const [stdout, stderr, code] = await Promise.all([
          new Response(child.stdout).text(),
          new Response(child.stderr).text(),
          child.exited,
        ]);
        if (code !== 0) throw new Error(`Journey failed (${code}): ${stderr}`);
        if (stderr) process.stderr.write(stderr);
        results.push({ run: run + 1, ...JSON.parse(stdout) });
      }
    }
  }
  const revision = Bun.spawnSync(["git", "rev-parse", "HEAD"])
    .stdout.toString()
    .trim();
  const summary = [100, 1000].flatMap((historySize) =>
    streamIntervals.map((streamEvery) => {
      const group = results.filter(
        (r) => r.historySize === historySize && r.streamEvery === streamEvery,
      );
      const median = (values: number[]) => {
        const sorted = [...values].sort((a, b) => a - b);
        return (
          (sorted[Math.floor((sorted.length - 1) / 2)] +
            sorted[Math.floor(sorted.length / 2)]) /
          2
        );
      };
      const inputP95s = group.map(
        (r) =>
          ("wheelToFrameMs" in r ? r.wheelToFrameMs : r.typingToCapturedFrameMs)
            .p95 ?? 0,
      );
      return {
        historySize,
        streamEvery,
        transcriptTraversals: group.map((r) => r.work.transcriptTraversals),
        [scrolling ? "wheelP95MsMedian" : "typingP95MsMedian"]:
          median(inputP95s),
        [scrolling ? "wheelP95MsRange" : "typingP95MsRange"]: [
          Math.min(...inputP95s),
          Math.max(...inputP95s),
        ],
        ...(scrolling
          ? {
              layoutReads: group.map((r) =>
                "layoutReads" in r.work ? r.work.layoutReads : 0,
              ),
              streamAndWheelP95MsMedian:
                streamEvery > 0
                  ? median(
                      group.map((r) =>
                        "streamAndWheelToFrameMs" in r
                          ? (r.streamAndWheelToFrameMs.p95 ?? 0)
                          : 0,
                      ),
                    )
                  : null,
            }
          : {}),
        cpuMsMedian: median(group.map((r) => r.cpuMs)),
      };
    }),
  );
  const report = {
    revision,
    journey,
    dirty: Bun.spawnSync(["git", "status", "--porcelain"]).stdout.length > 0,
    bun: Bun.version,
    opentui: corePackage.version,
    react: reactPackage.version,
    platform: process.platform,
    arch: process.arch,
    cpu: cpus()[0]?.model,
    useThread: false,
    runs,
    summary,
    results,
  };
  if (process.argv[3]) {
    await Bun.write(process.argv[3], `${JSON.stringify(report, null, 2)}\n`);
    console.log(JSON.stringify({ ...report, results: undefined }, null, 2));
  } else {
    console.log(JSON.stringify(report, null, 2));
  }
} finally {
  await rm(home, { recursive: true, force: true });
}
