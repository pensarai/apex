# Bug Bounty Triage — Worked Example

This directory shows two ways to turn the `/triage` skill into a runnable workflow:

1. **`run-cli.ts`** — minimal programmatic invocation against a fixture report. Useful for "does this work end-to-end on my machine" verification.
2. **`webhook-server.ts`** — production-shape integration: an HTTP server that validates HackerOne webhook signatures and dispatches `report_created` events into the triage workflow with bounded concurrency.

Both scripts call the same `runTriageWorkflow` entry point that powers `pensar triage` on the CLI — they're thin wrappers over the workflow, not separate implementations.

---

## Directory layout

```
examples/bug-bounty-triage/
├── README.md                       # this file
├── run-cli.ts                      # one-shot programmatic example
├── webhook-server.ts               # webhook-driven workflow
└── fixtures/
    ├── h1-webhook-report.json      # realistic `report_created` payload
    └── .apex/
        └── bug-bounty/
            ├── scope.md
            ├── engagement.md
            └── business-context.md
```

The `fixtures/.apex/bug-bounty/` files are the convention-based program-context inputs the skill reads from a repo's `cwd`. They are real, plausible documents you can adapt to your own program.

---

## 1. Quick try — `run-cli.ts`

The simplest path. Reads the fixture HackerOne webhook payload, runs the full pipeline (parse → scope → dup → live-verify → CVSS → threat-model alignment → decide → remediation draft), and writes outputs to `examples/bug-bounty-triage/out/`.

```bash
# From the repo root. Requires an AI provider configured (PENSAR_API_KEY,
# ANTHROPIC_API_KEY, OPENAI_API_KEY, etc. — same as `pensar` CLI).
bun run examples/bug-bounty-triage/run-cli.ts \
  --target https://staging.acme-shop.example.com
```

After completion you'll have:

```
examples/bug-bounty-triage/out/
├── triage.md          # human-readable triage report (with embedded remediation)
└── decision.json      # schema-validated TriageResult
```

Open `triage.md` — the `## Suggested HackerOne action` section shows the recommended H1 state transition and a paste-ready reply to the reporter.

> **Note on live verification.** The fixture targets `staging.acme-shop.example.com`, which won't resolve from your machine. The live-verification step will report `reproduced: false` with the corresponding network errors as evidence. That's expected — point `--target` at a host you actually control to see a real reproduction.

---

## 2. Production shape — `webhook-server.ts`

Run an always-on HTTP server that turns the skill into a workflow driven directly by HackerOne. Every `report_created` event spawns a triage job. Outputs land per-report at `out/<report-id>/`.

### Configure your HackerOne program

1. Navigate to `Engagements → <Program> → Settings → Automation → Webhooks`.
2. Click **Add webhook**.
3. Set the **URL** to wherever you'll host this server (during development, expose it via [ngrok](https://ngrok.com/) or [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) so HackerOne can reach localhost).
4. Set the **secret** — copy this; you'll pass it to the server below.
5. Under **Events**, subscribe to `report_created` (and any state-transition events you want to react to in the future).

### Run the server

```bash
H1_WEBHOOK_SECRET="<the secret you set in step 4>" \
TRIAGE_TARGET="https://staging.acme-shop.example.com" \
  bun run examples/bug-bounty-triage/webhook-server.ts
```

Optional environment variables:

| Var | Default | Purpose |
|---|---|---|
| `PORT` | `8787` | HTTP listen port |
| `TRIAGE_MAX_CONCURRENCY` | `2` | Max concurrent triage jobs |

The server logs each accepted webhook, the matched event, and per-job progress.

### What it does on each `report_created`

1. Reads the raw request body (raw bytes are required for HMAC verification).
2. Verifies `X-H1-Signature` (`sha256=<hex digest>`) against the configured secret using a timing-safe comparison. Mismatches return `401`.
3. Filters on `X-H1-Event` — only `report_created` triggers triage; everything else returns `202 Ignored`.
4. Writes the raw payload to `out/<report-id>/h1-payload.json`.
5. Enqueues a triage job (bounded by `TRIAGE_MAX_CONCURRENCY`).
6. Returns `202 Accepted` immediately so HackerOne doesn't retry while a long-running triage job is still working.
7. The triage job calls `runTriageWorkflow` with `source: "hackerone"`, which activates the deterministic H1 JSON parser fast-path.
8. Outputs are written to `out/<report-id>/triage.md` + `decision.json`.

### Health check

```bash
curl http://localhost:8787/health
# → { "status": "ok", "active": 0, "queued": 0 }
```

### What's *not* production-ready

This example is deliberately minimal — it demonstrates the integration shape, not a hardened deployment. Before running this for real, add:

- **Persistent queue** (Redis / SQS / pg) — the in-memory pool drops jobs on restart.
- **Idempotency on `X-H1-Delivery`** — HackerOne retries; track delivered IDs to avoid re-running triage on the same event.
- **Per-program secrets** — multi-tenant programs need a webhook → secret lookup.
- **Observability** — structured logs, error reporting (Sentry), per-job tracing.
- **Slack / PagerDuty notifications** — wire the decision outcome into your existing on-call rotation.

---

## Customising for your own program

Drop a `.apex/bug-bounty/` directory into your real repo (next to `package.json` or wherever the skill is invoked from):

```
your-repo/
├── .apex/
│   └── bug-bounty/
│       ├── scope.md             # what's in/out of scope
│       ├── engagement.md         # rules of engagement, excluded vuln classes
│       └── business-context.md   # known accepted risks, asset criticality
└── ...
```

The fixtures here are starting points — copy them into your repo, then edit to match your own program. The skill picks them up automatically from `cwd` when invoked.

For threat-model alignment, also generate a threat model with the existing `pensar threat-model` workflow and write its output to `.apex/threat-models/<date>.md`. The triage skill auto-loads the most recently modified file there.

---

## See also

- The triage skill source: [`src/core/agents/specialized/reportTriage/`](../../src/core/agents/specialized/reportTriage)
- The workflow entry point: [`src/core/workflows/triage.ts`](../../src/core/workflows/triage.ts)
- The skill definition: [`src/core/skills/builtins/triage.ts`](../../src/core/skills/builtins/triage.ts)
- HackerOne webhook docs: <https://api.hackerone.com/webhooks/>
- HackerOne report-state machine: <https://docs.hackerone.com/en/articles/8475030-report-states>
