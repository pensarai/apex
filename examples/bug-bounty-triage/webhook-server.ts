/**
 * examples/bug-bounty-triage/webhook-server.ts
 *
 * Production-shape integration: a tiny HTTP server that turns the
 * `/triage` skill into an always-on workflow driven by HackerOne webhooks.
 *
 * Flow per inbound webhook:
 *   1. Read raw body.
 *   2. Verify `X-H1-Signature` (HMAC-SHA256 hex with `sha256=` prefix) using
 *      a constant-time comparison.
 *   3. Route by `X-H1-Event` — only `report_created` triggers triage.
 *   4. Persist the raw payload to `out/<report-id>/h1-payload.json` so the
 *      workflow can read it from disk.
 *   5. Spawn `runTriageWorkflow` on a bounded concurrency pool.
 *   6. Outputs land at `out/<report-id>/triage.md` and `decision.json`.
 *
 * Run:
 *   H1_WEBHOOK_SECRET="<your-shared-secret>" \\
 *   TRIAGE_TARGET="https://staging.acme-shop.example.com" \\
 *     bun run examples/bug-bounty-triage/webhook-server.ts
 *
 * Point your HackerOne program's webhook (`Engagements → Program → Settings →
 * Automation → Webhooks`) at `https://<your-host>/webhook/hackerone` and
 * subscribe to the `report_created` event.
 *
 * This is illustrative — for real deployment add: persistent queue (vs. the
 * in-memory pool), retries on failure, per-program secrets, observability
 * (sentry / structured logs), and idempotency on `X-H1-Delivery`.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { buildAuthConfig } from "../../src/core/ai";
import { config as appConfig } from "../../src/core/config";
import { AgentEventBus } from "../../src/core/eventBus";
import { runTriageWorkflow } from "../../src/core/workflows/triage";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const HERE = dirname(new URL(import.meta.url).pathname);
const OUTPUT_ROOT = join(HERE, "out");

const PORT = Number(process.env.PORT ?? "8787");
const SECRET = process.env.H1_WEBHOOK_SECRET ?? "";
const TARGET = process.env.TRIAGE_TARGET ?? "";
const MAX_CONCURRENCY = Number(process.env.TRIAGE_MAX_CONCURRENCY ?? "2");

if (!TARGET) {
  console.error(
    "TRIAGE_TARGET env var is required (live URL used for PoC re-verification)",
  );
  process.exit(1);
}
if (!SECRET) {
  console.warn(
    "[warn] H1_WEBHOOK_SECRET is empty — signature verification will reject ALL inbound requests. Set it to your HackerOne webhook secret.",
  );
}

// ---------------------------------------------------------------------------
// Signature verification — RFC-aligned with HackerOne's `sha256=<hexdigest>`
// scheme. The first split element is `sha256` and the second is the HMAC
// digest of the raw request body.
// ---------------------------------------------------------------------------

function verifyHackerOneSignature(
  rawBody: string,
  header: string | null,
): boolean {
  if (!header || !SECRET) return false;

  const [algo, signature] = header.split("=", 2);
  if (algo !== "sha256" || !signature) return false;

  const expected = createHmac("sha256", SECRET).update(rawBody).digest("hex");

  // Buffer.byteLength + timingSafeEqual would throw on length mismatch — guard
  // it first to keep the comparison constant-time.
  if (expected.length !== signature.length) return false;
  return timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

// ---------------------------------------------------------------------------
// Concurrency-limited job pool
// ---------------------------------------------------------------------------

let active = 0;
const queue: Array<() => Promise<void>> = [];

function enqueue(job: () => Promise<void>): void {
  queue.push(job);
  drain();
}

function drain(): void {
  while (active < MAX_CONCURRENCY && queue.length > 0) {
    const next = queue.shift();
    if (!next) break;
    active++;
    next()
      .catch((err) => {
        console.error("[triage-job] failed:", err);
      })
      .finally(() => {
        active--;
        drain();
      });
  }
}

// ---------------------------------------------------------------------------
// Report-created handler — does the actual triage
// ---------------------------------------------------------------------------

interface HackerOneEnvelope {
  data?: { relationships?: { report?: { data?: { id?: string } } } };
  included?: Array<{ id?: string; type?: string }>;
}

function extractReportId(payload: unknown): string {
  const env = payload as HackerOneEnvelope;
  const id = env.data?.relationships?.report?.data?.id;
  if (id) return id;
  // Fallback: walk `included` for the first `type: "report"` resource.
  const fromIncluded = env.included?.find((i) => i.type === "report")?.id;
  return fromIncluded ?? `unknown-${Date.now()}`;
}

async function triageOne(rawPayload: string): Promise<void> {
  const parsed: unknown = JSON.parse(rawPayload);
  const reportId = extractReportId(parsed);
  const outDir = join(OUTPUT_ROOT, reportId);
  await mkdir(outDir, { recursive: true });

  const payloadPath = join(outDir, "h1-payload.json");
  await writeFile(payloadPath, rawPayload, "utf-8");

  console.log(`[triage-job] report=${reportId} starting`);

  const bus = new AgentEventBus();
  bus.on("tool-call-complete", (e) =>
    console.log(`[triage-job] report=${reportId} → ${e.toolName}`),
  );
  bus.on("error", (e) =>
    console.error(`[triage-job] report=${reportId} error:`, e.error),
  );

  const pensarConfig = await appConfig.get();

  try {
    const { result, triageMarkdownPath, decisionJsonPath } =
      await runTriageWorkflow({
        reportPath: payloadPath,
        target: TARGET,
        cwd: process.cwd(),
        output: outDir,
        source: "hackerone",
        eventBus: bus,
        authConfig: buildAuthConfig(pensarConfig),
      });

    console.log(
      `[triage-job] report=${reportId} done — ${result.decision.outcome} (${result.decision.reason}) → ${result.decision.suggestedHackerOneState ?? "no H1 state"}`,
    );
    console.log(`[triage-job] report=${reportId} triage=${triageMarkdownPath}`);
    console.log(`[triage-job] report=${reportId} decision=${decisionJsonPath}`);
  } catch (err) {
    console.error(`[triage-job] report=${reportId} workflow error:`, err);
  }
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

const server = Bun.serve({
  port: PORT,
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "GET" && url.pathname === "/health") {
      return Response.json({
        status: "ok",
        active,
        queued: queue.length,
      });
    }

    if (req.method !== "POST" || url.pathname !== "/webhook/hackerone") {
      return new Response("Not found", { status: 404 });
    }

    // 1. Read raw body — must be the raw bytes for HMAC verification.
    const rawBody = await req.text();

    // 2. Verify signature.
    const sigHeader = req.headers.get("X-H1-Signature");
    if (!verifyHackerOneSignature(rawBody, sigHeader)) {
      console.warn(
        `[webhook] rejected — signature mismatch (delivery=${req.headers.get("X-H1-Delivery") ?? "?"})`,
      );
      return new Response("Invalid signature", { status: 401 });
    }

    // 3. Route by event.
    const event = req.headers.get("X-H1-Event");
    if (event !== "report_created") {
      console.log(`[webhook] ignoring event=${event}`);
      return new Response("Ignored", { status: 202 });
    }

    // 4. Enqueue triage. We respond 202 immediately so HackerOne doesn't
    //    retry on long-running triage jobs (verification + remediation can
    //    take minutes).
    enqueue(() => triageOne(rawBody));

    return new Response("Accepted", { status: 202 });
  },
});

console.log(
  `[webhook] listening on http://localhost:${server.port}/webhook/hackerone`,
);
console.log(`[webhook] target=${TARGET} max_concurrency=${MAX_CONCURRENCY}`);
console.log(`[webhook] outputs land under ${OUTPUT_ROOT}/<report-id>/`);
