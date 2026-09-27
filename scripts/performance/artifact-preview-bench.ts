/**
 * PR07 benchmark: bounded artifact preview reads.
 *
 * Writes a 32 MiB ASCII whitebox artifact through the production writer, then
 * reads it through the production readWhiteboxArtifact path, reporting wall
 * time, RSS delta, and (on implementations that expose it) the actual bytes
 * read by the preview.
 *
 * Usage: bun run scripts/performance/artifact-preview-bench.ts --label candidate
 * Emits one JSON line per run; the coordinating harness alternates this
 * against the same script on the baseline commit in fresh processes.
 */

import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { SessionInfo } from "../../src/core/session";
import {
  readWhiteboxArtifact,
  writeWhiteboxArtifact,
} from "../../src/core/whitebox/artifacts";

const FIXTURE_CHARS = 32 * 1024 * 1024;
const ITERATIONS = 7;

function gc(): void {
  if (typeof Bun !== "undefined") Bun.gc(true);
  else globalThis.gc?.();
}

function mockSession(rootPath: string): SessionInfo {
  return {
    id: "ses_bench",
    version: "1.0.0",
    targets: [],
    time: { created: Date.now(), updated: Date.now() },
    rootPath,
    logsPath: join(rootPath, "logs"),
    findingsPath: join(rootPath, "findings"),
    scratchpadPath: join(rootPath, "scratchpad"),
    pocsPath: join(rootPath, "pocs"),
    config: {},
  };
}

function argLabel(): string {
  const idx = process.argv.indexOf("--label");
  return idx > 0 ? (process.argv[idx + 1] ?? "unlabeled") : "unlabeled";
}

const root = await mkdtemp(join(tmpdir(), "apex-pr07-bench-"));
const session = mockSession(root);
const content = "a".repeat(FIXTURE_CHARS);
const ref = await writeWhiteboxArtifact({
  session,
  type: "raw-output",
  name: "bench",
  content,
  description: "32 MiB ASCII preview benchmark fixture",
});

gc();
const iterations: Array<{
  ms: number;
  rssBefore: number;
  rssAfter: number;
}> = [];
const marker =
  "\n\n(truncated - read the artifact in smaller chunks if needed)";
const artifactFile = join(
  session.logsPath,
  "whitebox",
  ref.path.split("/").pop() ?? "",
);
for (let i = 0; i < ITERATIONS; i++) {
  gc();
  const rssBefore = process.memoryUsage.rss();
  const t0 = performance.now();
  const read = await readWhiteboxArtifact({ session, path: ref.path });
  const ms = performance.now() - t0;
  const rssAfter = process.memoryUsage.rss();
  if (
    !read.truncated ||
    read.content.length !== 40_000 + marker.length ||
    !read.content.endsWith(marker)
  ) {
    console.error(
      "unexpected preview shape",
      read.truncated,
      read.content.length,
    );
    process.exit(1);
  }
  iterations.push({ ms, rssBefore, rssAfter });
}

let bytesRead: number | null = null;
try {
  const { readTextPrefix } = await import("../../src/core/whitebox/artifacts");
  bytesRead = (await readTextPrefix(artifactFile, 40_000)).bytesRead;
} catch {
  bytesRead = null; // baseline: internal helper absent
}

const parityWhole = await readFile(artifactFile, "utf-8");
if (parityWhole.length !== FIXTURE_CHARS) {
  console.error("fixture corrupted", parityWhole.length);
  process.exit(1);
}
const runtime =
  typeof Bun !== "undefined" ? `bun ${Bun.version}` : `node ${process.version}`;
console.log(
  JSON.stringify({
    label: argLabel(),
    runtime,
    fixture: { chars: FIXTURE_CHARS, bytes: Buffer.byteLength(content) },
    parityFileSize: parityWhole.length,
    iterations,
    medianMs: iterations.map((i) => i.ms).sort((a, b) => a - b)[
      Math.floor(ITERATIONS / 2)
    ],
    bytesRead,
  }),
);
await rm(root, { recursive: true, force: true });
