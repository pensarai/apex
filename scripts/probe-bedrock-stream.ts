#!/usr/bin/env tsx
/**
 * Transport-level dead-socket probe. Strips away the 40-step threat-model agent
 * and just fires N concurrent `streamText` calls that elicit a LONG response,
 * so we can measure the RAW rate at which provider streams go byte-silent
 * (half-open sockets) — and how that rate moves with runtime, inference
 * profile, and concurrency.
 *
 * The wedge signal comes from the same `StreamTelemetry` wired into the bedrock
 * fetch (`utils.ts`): a `[stream-telem] ... WEDGE` line == one dead stream
 * caught by `idleGuardedResponse`. Run with `PENSAR_STREAM_DEBUG=1`.
 *
 * Isolate causes by varying one knob at a time:
 *   # runtime: Bun (sandbox runtime) vs Node (has undici keepalive)
 *   PENSAR_STREAM_DEBUG=1 AWS_REGION=us-east-1 bun --bun scripts/probe-bedrock-stream.ts --count 20 --concurrency 4
 *   PENSAR_STREAM_DEBUG=1 AWS_REGION=us-east-1 npx tsx       scripts/probe-bedrock-stream.ts --count 20 --concurrency 4
 *   # profile: global cross-region vs us regional
 *   ... --model global.anthropic.claude-opus-4-6-v1
 *   ... --model us.anthropic.claude-opus-4-6-v1
 *   # concurrency
 *   ... --concurrency 1   vs   --concurrency 8
 *
 * Lower idle window to fail faster while probing: PENSAR_STREAM_IDLE_TIMEOUT_MS=45000
 */

import { streamText } from "ai";
import pLimit from "p-limit";
import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import type { AIAuthConfig, AIModel } from "../src/core/ai";
import { getProviderModel } from "../src/core/ai/utils";

function arg(flag: string, fallback: string): string {
  const i = process.argv.indexOf(flag);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

const MODEL = arg("--model", "global.anthropic.claude-opus-4-6-v1") as AIModel;
const COUNT = Number(arg("--count", "20"));
const CONCURRENCY = Number(arg("--concurrency", "4"));
const MAX_TOKENS = Number(arg("--max-tokens", "8000"));

// A prompt engineered to produce a long, steady token stream — the condition
// under which the half-open socket shows up.
const PROMPT =
  "Write an exhaustive, deeply technical 6000-word reference on the internals " +
  "of distributed consensus (Paxos, Raft, Viewstamped Replication, Zab): leader " +
  "election, log replication, membership changes, snapshotting, and the exact " +
  "failure modes each handles. Use long prose paragraphs, not bullet points.";

const captured: string[] = [];
const origErr = console.error.bind(console);
console.error = (...a: unknown[]) => {
  captured.push(a.map((x) => (typeof x === "string" ? x : String(x))).join(" "));
  origErr(...a);
};

async function main() {
  if (!process.env.AWS_REGION && !process.env.AWS_DEFAULT_REGION) {
    origErr("Set AWS_REGION (e.g. us-east-1).");
    process.exit(1);
  }
  const authConfig: AIAuthConfig = {
    bedrock: { credentialProvider: fromNodeProviderChain() },
  };
  const model = getProviderModel(MODEL, authConfig);

  origErr("=".repeat(72));
  origErr("BEDROCK STREAM DEAD-SOCKET PROBE");
  origErr(`runtime     : ${typeof (globalThis as { Bun?: unknown }).Bun !== "undefined" ? "bun" : "node"}`);
  origErr(`model       : ${MODEL}`);
  origErr(`count       : ${COUNT}   concurrency: ${CONCURRENCY}   maxTokens: ${MAX_TOKENS}`);
  origErr(`region      : ${process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION}`);
  origErr(`idleTimeout : ${process.env.PENSAR_STREAM_IDLE_TIMEOUT_MS ?? "90000 (default)"}`);
  origErr("=".repeat(72));

  const limit = pLimit(CONCURRENCY);
  const t0 = Date.now();
  const results = await Promise.allSettled(
    Array.from({ length: COUNT }, (_, i) =>
      limit(async () => {
        const started = Date.now();
        let bytes = 0;
        try {
          const res = streamText({
            model,
            prompt: PROMPT,
            maxOutputTokens: MAX_TOKENS,
            // One stream attempt per call so stream-count == call-count.
            maxRetries: 0,
          });
          for await (const part of res.fullStream) {
            if (part.type === "text-delta") bytes += part.text?.length ?? 0;
          }
          return { i, ok: true, ms: Date.now() - started, chars: bytes };
        } catch (err) {
          return {
            i,
            ok: false,
            ms: Date.now() - started,
            chars: bytes,
            err: err instanceof Error ? err.message : String(err),
          };
        }
      }),
    ),
  );

  const calls = results.map((r) => (r.status === "fulfilled" ? r.value : null)).filter(Boolean) as Array<{ i: number; ok: boolean; ms: number; chars: number; err?: string }>;
  const ok = calls.filter((c) => c.ok);
  const failed = calls.filter((c) => !c.ok);
  const wedges = captured.filter((l) => l.includes("[stream-telem]") && l.includes("WEDGE"));

  origErr(`\n${"=".repeat(72)}`);
  origErr("PROBE REPORT");
  origErr("=".repeat(72));
  origErr(`wall clock        : ${Math.round((Date.now() - t0) / 1000)}s`);
  origErr(`calls             : ${calls.length}`);
  origErr(`  ├─ completed     : ${ok.length}`);
  origErr(`  └─ errored       : ${failed.length}`);
  origErr(`stream WEDGES      : ${wedges.length}`);
  origErr(`wedge rate         : ${calls.length ? ((wedges.length / calls.length) * 100).toFixed(1) : "0"}%  (wedges / calls)`);
  if (failed.length) {
    origErr("\n── error samples ──");
    for (const f of failed.slice(0, 8)) origErr(`   call#${f.i} after ${Math.round(f.ms / 1000)}s, ${f.chars} chars: ${f.err}`);
  }
  origErr("=".repeat(72));
  process.exit(0);
}

main().catch((e) => {
  origErr("probe fatal:", e);
  process.exit(1);
});
