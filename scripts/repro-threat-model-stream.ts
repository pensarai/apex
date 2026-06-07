#!/usr/bin/env tsx
/**
 * Fast, faithful reproduction harness for the threat-model `response`-stream
 * wedge (the `document_endpoint` hang). Instead of waiting 75–90 minutes for a
 * full whitebox recon, this drives the EXACT child path that wedges —
 * `generateThreatModelForEndpoint` → `CodeAgent.consume()` → the Pensar provider
 * SSE stream — directly, in a loop, against a real local codebase, using the
 * same `gateway.pensar.dev` → Bedrock path production uses.
 *
 * IMPORTANT — provider fidelity. The deployed SANDBOX does NOT use the Pensar
 * gateway; `buildSandboxAuthConfig()` injects `{ bedrock: { credentialProvider:
 * fromNodeProviderChain() } }` and the platform `pentestModel`
 * (`global.anthropic.claude-opus-4-6-v1`) resolves to the **bedrock** provider
 * (`createAmazonBedrock`). So the wedge lives on the Bedrock stream path, not
 * `pensar.ts`/`pensarSSE.ts`. This harness therefore defaults to
 * `--provider bedrock` to faithfully reproduce the sandbox. (`--provider pensar`
 * exercises the CLI gateway path instead, using `~/.pensar/config.json`.)
 *
 * For bedrock you need AWS creds in the environment (e.g. `AWS_PROFILE` +
 * `AWS_REGION`); the default AWS provider chain is used, matching the sandbox.
 * The internal `pLimit(THREAT_MODEL_CONCURRENCY)` governs true parallelism, so
 * the concurrency profile matches prod.
 *
 * Turn on byte-level telemetry to see WHY a stream stalls (dead vs dribbling):
 *
 *   PENSAR_STREAM_DEBUG=1 bun --bun scripts/repro-threat-model-stream.ts \
 *     --codebase /path/to/repo --loops 5 --endpoints 8
 *
 * Flags:
 *   --codebase <path>   Repo the threat-model agent analyzes. Default: the apex
 *                       worktree root (plenty of real endpoints).
 *   --model <id>        Model id. Default: pensar:global.anthropic.claude-opus-4-6-v1
 *                       (the platform `pentestModel` threat-model children inherit).
 *   --loops <n>         How many times to run the endpoint batch. Default: 3.
 *   --endpoints <n>     Endpoints fired per loop (gated to 4 by the limiter).
 *                       Default: 8.
 *   --stall-ms <n>      Per-call duration above which we flag a SLOW call in the
 *                       report (does not abort — the liveness mechanism owns that).
 *                       Default: 180000 (3m).
 */

import path from "node:path";
import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import { config } from "../src/core/config";
import { buildAuthConfig, type AIAuthConfig, type AIModel } from "../src/core/ai";
import { AgentEventBus } from "../src/core/eventBus";
import { sessions } from "../src/core/session";
import {
  generateThreatModelForEndpoint,
  type GenerateThreatModelInput,
} from "../src/core/agents/offSecAgent/tools/threatModelGenerator";
import type { ToolContext } from "../src/core/agents/offSecAgent/tools/types";

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

function parseArgs(argv: string[]) {
  const get = (flag: string, fallback?: string): string | undefined => {
    const i = argv.indexOf(flag);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : fallback;
  };
  const worktreeRoot = path.resolve(import.meta.dirname, "..");
  const provider = (get("--provider", "bedrock") ?? "bedrock") as
    | "bedrock"
    | "pensar";
  // Default model matches the platform `pentestModel` for the active provider.
  const defaultModel =
    provider === "pensar"
      ? "pensar:anthropic.claude-opus-4-6-v1"
      : "global.anthropic.claude-opus-4-6-v1";
  return {
    provider,
    codebase: path.resolve(get("--codebase", worktreeRoot) ?? worktreeRoot),
    model: (get("--model", defaultModel) ?? "") as AIModel,
    loops: Number(get("--loops", "3")),
    endpoints: Number(get("--endpoints", "8")),
    stallMs: Number(get("--stall-ms", String(3 * 60 * 1000))),
  };
}

// ---------------------------------------------------------------------------
// Endpoint corpus — realistic specs that elicit a LARGE structured `response`
// (the payload size is what correlates with the wedge). Cycled to fill a batch.
// ---------------------------------------------------------------------------

const ENDPOINT_CORPUS: GenerateThreatModelInput[] = [
  {
    appName: "auth-service",
    routePath: "/api/auth/login",
    method: "POST",
    authRequired: false,
    description:
      "Primary credential login. Accepts email + password, issues a session JWT and a refresh-token cookie. Rate-limited; supports optional TOTP second factor and 'remember this device' trust tokens.",
  },
  {
    appName: "auth-service",
    routePath: "/api/auth/oauth/callback",
    method: "GET",
    authRequired: false,
    description:
      "OAuth2 / WorkOS SSO callback. Exchanges an authorization code for tokens, provisions or links a user, and establishes a session. Handles state/nonce validation and IdP-initiated flows.",
  },
  {
    appName: "billing-service",
    routePath: "/api/billing/webhooks/stripe",
    method: "POST",
    authRequired: false,
    description:
      "Stripe webhook receiver. Verifies the signature header, then mutates subscription state, seat counts, and invoices. Idempotency keys guard replays; failures must not double-charge.",
  },
  {
    appName: "billing-service",
    routePath: "/api/billing/subscription",
    method: ["GET", "PUT", "DELETE"],
    authRequired: true,
    description:
      "Read, upgrade/downgrade, and cancel the caller's workspace subscription. Plan changes are proration-sensitive and gate feature flags across the platform.",
  },
  {
    appName: "workspace-api",
    routePath: "/api/workspaces/:id/members",
    method: ["GET", "POST", "DELETE"],
    authRequired: true,
    description:
      "Manage workspace membership and roles (owner/admin/member). Invites send email, mutate RBAC, and can escalate privileges. Cross-tenant isolation is critical here.",
  },
  {
    appName: "workspace-api",
    routePath: "/api/workspaces/:id/api-keys",
    method: ["GET", "POST", "DELETE"],
    authRequired: true,
    description:
      "Create, list, and revoke long-lived workspace API keys. Keys are shown once at creation, hashed at rest, and grant programmatic access scoped to the workspace.",
  },
  {
    appName: "scan-orchestrator",
    routePath: "/api/scans/:id/launch",
    method: "POST",
    authRequired: true,
    description:
      "Launch a pentest/recon scan against a target. Mints a sandbox JWT, dispatches an ephemeral agent, and streams events. Server-side scope validation prevents launching against out-of-scope hosts.",
  },
  {
    appName: "scan-orchestrator",
    routePath: "/api/agent/events/emit",
    method: "POST",
    authRequired: true,
    description:
      "Sandbox-to-server event sink. Derives workspaceId/scanId/issueId from JWT claims (never the body), validates the realtime event allowlist, and fans out to MQTT + the archival log table.",
  },
  {
    appName: "repo-integration",
    routePath: "/api/github/webhooks",
    method: "POST",
    authRequired: false,
    description:
      "GitHub App webhook. Verifies the HMAC signature, processes installation/push/PR events, and triggers code analysis. Replay and signature-spoofing are the dominant threats.",
  },
  {
    appName: "files-service",
    routePath: "/api/files/upload",
    method: "POST",
    authRequired: true,
    description:
      "Direct-to-S3 presigned upload issuer plus a multipart fallback. Validates content-type and size, scopes the object key to the workspace, and guards against path traversal and SSRF in the callback URL.",
  },
];

function buildBatch(n: number): GenerateThreatModelInput[] {
  const out: GenerateThreatModelInput[] = [];
  for (let i = 0; i < n; i++) {
    const base = ENDPOINT_CORPUS[i % ENDPOINT_CORPUS.length];
    // Vary the app name across cycles so concurrent subagentIds stay unique.
    const cycle = Math.floor(i / ENDPOINT_CORPUS.length);
    out.push(cycle === 0 ? base : { ...base, appName: `${base.appName}-${cycle}` });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Console tap — capture telemetry + abandon lines without losing live output.
// ---------------------------------------------------------------------------

const captured: string[] = [];
function tapConsole() {
  const origErr = console.error.bind(console);
  const origLog = console.log.bind(console);
  const tap =
    (orig: (...a: unknown[]) => void) =>
    (...args: unknown[]) => {
      try {
        captured.push(args.map((a) => (typeof a === "string" ? a : String(a))).join(" "));
      } catch {
        /* ignore */
      }
      orig(...args);
    };
  console.error = tap(origErr) as typeof console.error;
  console.log = tap(origLog) as typeof console.log;
}

function field(line: string, key: string): string | undefined {
  const m = line.match(new RegExp(`${key}=([^\\s]+)`));
  return m?.[1];
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

type CallResult = {
  endpoint: string;
  ms: number;
  outcome: "output" | "null" | "error";
  error?: string;
};

async function main() {
  const args = parseArgs(process.argv.slice(2));
  tapConsole();

  let authConfig: AIAuthConfig;
  if (args.provider === "pensar") {
    const cfg = await config.get();
    authConfig = buildAuthConfig({
      anthropicAPIKey: cfg.anthropicAPIKey,
      pensarAPIKey: cfg.pensarAPIKey,
      accessToken: cfg.accessToken,
      refreshToken: cfg.refreshToken,
      workspaceId: cfg.workspaceId,
      gatewaySigningKey: cfg.gatewaySigningKey,
      gatewayUrl: cfg.gatewayUrl,
    });
    if (!authConfig.accessToken && !authConfig.pensarAPIKey) {
      console.error(
        "No Pensar auth in ~/.pensar/config.json. Run the apex CLI `/login` first.",
      );
      process.exit(1);
    }
  } else {
    // Bedrock — mirror buildSandboxAuthConfig() EXACTLY: hand the bedrock
    // provider `fromNodeProviderChain()` so SigV4 signing resolves creds from
    // the default AWS chain (AWS_PROFILE / env / SSO), just like the sandbox.
    authConfig = {
      bedrock: {
        credentialProvider: fromNodeProviderChain(),
      },
    };
    if (!process.env.AWS_REGION && !process.env.AWS_DEFAULT_REGION) {
      console.error(
        "Bedrock provider needs AWS_REGION (e.g. AWS_REGION=us-east-1) in the environment.",
      );
      process.exit(1);
    }
  }

  console.log("=".repeat(80));
  console.log("THREAT-MODEL STREAM WEDGE REPRO");
  console.log("=".repeat(80));
  console.log(`provider    : ${args.provider}${args.provider === "bedrock" ? "  (faithful to deployed sandbox)" : "  (CLI gateway path)"}`);
  console.log(`codebase    : ${args.codebase}`);
  console.log(`model       : ${args.model}`);
  console.log(`loops       : ${args.loops}`);
  console.log(`endpoints/loop: ${args.endpoints} (internal limiter gates true parallelism)`);
  if (args.provider === "bedrock") {
    console.log(`aws region  : ${process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION}`);
    console.log(`aws profile : ${process.env.AWS_PROFILE ?? "(default chain)"}`);
  } else {
    console.log(`workspaceId : ${authConfig.workspaceId ?? "(none)"}`);
    console.log(`gateway     : ${authConfig.gatewayUrl ?? "https://gateway.pensar.dev (default)"}`);
  }
  console.log(`telemetry   : ${process.env.PENSAR_STREAM_DEBUG ? "ON" : "OFF (set PENSAR_STREAM_DEBUG=1)"}`);
  console.log("=".repeat(80));

  const session = await sessions.create({
    name: "Threat Model Wedge Repro",
    targets: [args.codebase],
    config: { mode: "operator", agentCwd: args.codebase },
  });

  const baseCtx: ToolContext = {
    session,
    agentCwd: args.codebase,
    model: args.model,
    authConfig,
    eventBus: new AgentEventBus(),
  };

  const allResults: CallResult[] = [];

  for (let loop = 1; loop <= args.loops; loop++) {
    const batch = buildBatch(args.endpoints);
    console.log(`\n── loop ${loop}/${args.loops} — firing ${batch.length} endpoints ──`);
    const loopStart = Date.now();

    const settled = await Promise.allSettled(
      batch.map(async (ep): Promise<CallResult> => {
        const label = `${ep.appName} ${ep.routePath}`;
        const t0 = Date.now();
        try {
          const out = await generateThreatModelForEndpoint(baseCtx, ep);
          return {
            endpoint: label,
            ms: Date.now() - t0,
            outcome: out ? "output" : "null",
          };
        } catch (err) {
          return {
            endpoint: label,
            ms: Date.now() - t0,
            outcome: "error",
            error: err instanceof Error ? err.message : String(err),
          };
        }
      }),
    );

    for (const s of settled) {
      if (s.status === "fulfilled") allResults.push(s.value);
    }
    console.log(`   loop ${loop} done in ${Math.round((Date.now() - loopStart) / 1000)}s`);
  }

  // -------------------------------------------------------------------------
  // Report
  // -------------------------------------------------------------------------
  const wedgeLines = captured.filter((l) => l.includes("[stream-telem]") && l.includes("WEDGE"));
  const abandonLines = captured.filter((l) => l.includes("abandoned ("));
  const total = allResults.length;
  const outputs = allResults.filter((r) => r.outcome === "output").length;
  const nulls = allResults.filter((r) => r.outcome === "null").length;
  const errors = allResults.filter((r) => r.outcome === "error").length;
  const slow = allResults.filter((r) => r.ms > args.stallMs);
  const durations = allResults.map((r) => r.ms).sort((a, b) => a - b);
  const pct = (p: number) =>
    durations.length ? durations[Math.min(durations.length - 1, Math.floor(p * durations.length))] : 0;

  console.log(`\n${"=".repeat(80)}`);
  console.log("REPORT");
  console.log("=".repeat(80));
  console.log(`threat-model calls : ${total}`);
  console.log(`  ├─ returned output : ${outputs}`);
  console.log(`  ├─ returned null   : ${nulls}  (heuristic fallback — wedged w/o captured response, or empty)`);
  console.log(`  └─ threw           : ${errors}`);
  console.log(`duration p50/p90/max: ${Math.round(pct(0.5) / 1000)}s / ${Math.round(pct(0.9) / 1000)}s / ${Math.round((durations.at(-1) ?? 0) / 1000)}s`);
  console.log(`slow (>${Math.round(args.stallMs / 1000)}s) : ${slow.length}`);
  console.log("");
  console.log(`stream WEDGES (telem) : ${wedgeLines.length}`);
  console.log(`liveness ABANDONS     : ${abandonLines.length}  (mechanism caught a wedge)`);
  const wedgeRate = total ? ((abandonLines.length / total) * 100).toFixed(1) : "0.0";
  console.log(`wedge rate            : ${wedgeRate}%  (abandons / calls)`);

  if (wedgeLines.length) {
    console.log("\n── WEDGE breakdown (dead vs dribbling) ──");
    let dead = 0;
    let dribbling = 0;
    for (const l of wedgeLines) {
      const sinceByte = Number(field(l, "msSinceLastByte") ?? "0");
      const sinceEvent = Number(field(l, "msSinceLastEvent") ?? "0");
      const phase = field(l, "phase");
      // No bytes for a long stretch ⇒ transport dead/half-open. Bytes recent but
      // no parsed events ⇒ alive but dribbling (model stuck mid-generation).
      const verdict = sinceByte >= 60_000 ? "DEAD" : "DRIBBLING";
      if (verdict === "DEAD") dead++;
      else dribbling++;
      console.log(`   ${verdict} phase=${phase} msSinceLastByte=${sinceByte} msSinceLastEvent=${sinceEvent}`);
    }
    console.log(`   → DEAD=${dead} DRIBBLING=${dribbling}`);
  }

  if (abandonLines.length) {
    console.log("\n── abandon reasons ──");
    for (const l of abandonLines.slice(0, 20)) console.log(`   ${l.trim()}`);
  }

  console.log(`\n${"=".repeat(80)}`);
  console.log(wedgeLines.length || abandonLines.length ? "✗ WEDGE REPRODUCED" : "✓ no wedge this run");
  console.log("=".repeat(80));

  // Don't wait on lingering sandbox/bus timers.
  process.exit(0);
}

main().catch((err) => {
  console.error("harness fatal:", err);
  process.exit(1);
});
