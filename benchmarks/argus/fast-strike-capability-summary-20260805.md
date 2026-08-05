# Apex agent runtime and fast-strike capability upgrade

## Executive summary

This change set improves Apex as a production offensive-security agent rather
than teaching it benchmark answers. The main result is a governed,
model-agnostic execution harness plus an explicit fast-strike objective
executor that can find and chain exploitable primitives until material impact
is demonstrated.

The latest implementation also closes the largest integrity gap found during
the qualification review: an `impact-proven` result must now cite a successful
tool observation by its exact `toolCallId` and `toolName`. Apex verifies that
the cited event occurred in the correct execution scope before accepting the
claim. Tool output remains in the existing trace and session stores; the
evidence ledger retains only metadata needed for the deterministic join.

The benchmark campaigns recorded 202 exact flag captures across four 71-test
runs: **202/284 (71.1%)**, up from a combined **177/284 (62.3%)** for the prior
Apex baselines. Exact flag capture is the primary score because a flag is proof
that an exploit chain achieved data exfiltration; it does not require the agent
to reproduce an assumed challenge storyline. Strict target-evidence judging is
reported separately and all mismatches remain failures under that metric.

## What changed

### Governed model-agnostic agent runtime

- Added a provider-neutral code runtime that lets capable models compose
  canonical Apex tools programmatically without changing tool identity or
  bypassing policy controls.
- Preserved direct contract tools while exposing the remaining capabilities
  through bounded code execution.
- Added execution discipline for shell, browser, workspace, and contract lanes,
  including serialization, timeouts, cancellation, repetition controls, and
  deterministic teardown.
- Added provider-neutral context compaction, continuation recovery, retry
  strategy, and reasoning-effort normalization so long exploit chains survive
  context pressure and transient provider failures.
- Hardened persistent-shell behavior so timeout, abort, partial-output salvage,
  queued execution, and child-process cleanup have deterministic semantics.

### Session, network, and OAST safety

- Bound network policy and execution policy to each agent session.
- Routed OAST and callback behavior through session-aware controls instead of
  allowing nested execution paths to bypass the parent contract.
- Added traffic, sandbox, destructive-action, and Playwright queue guards across
  direct and code-mode execution.
- Kept Console event identities, Daytona sandbox execution, OAST routing,
  finding/checkpoint tools, and production scope enforcement intact.

### Fast strike as an explicit objective executor

- Replaced the ambiguous global `solved: true` contract with objective-scoped
  statuses: `impact-proven`, `exhausted`, and `blocked`.
- Supports both intended production entry points:
  - a user supplies a custom scope and selects fast-strike mode; or
  - the pentest orchestrator spawns one fast-strike worker with one concrete
    exploitation goal.
- Runs one to three independent lanes with correlation labels and isolated
  workspaces, then cancels siblings after a verified success.
- Reserves bounded recovery time and allows a final recovery operator to combine
  compatible primitives and preserved artifacts instead of restarting broad
  reconnaissance.
- Protects scarce target state such as reset tokens, invitations, coupons, and
  one-shot jobs from being consumed by an unnecessary baseline request.
- Uses bounded, evidence-led offensive families for representation collisions,
  SSRF pivots, host construction, parser mismatches, token and MFA enforcement,
  native protocols, internal services, and multi-component exploit chains.
- Prefers the preinstalled Camoufox build, removing a normal-run network
  download and reducing browser-version drift.

### Trace-linked impact evidence

- Every fast-strike evidence item now contains a description, exact
  `toolCallId`, and exact `toolName`.
- `impact-proven` requires at least one completed observation from the active
  lane. Recovery may cite a preserved observation from any lane in the same
  objective.
- The runtime rejects unknown or cross-lane IDs, mismatched tool names,
  error-only results, the terminal `response` call, and ambiguous IDs reused in
  multiple execution scopes.
- Invalid claims receive a bounded correction opportunity. If the final result
  still lacks valid trace-linked evidence, it is downgraded to `exhausted`.
- The ledger stores no response bodies, credentials, flags, or other duplicate
  payloads. Existing trace/session persistence remains the source of truth.
- This establishes provenance, not semantic truth: Apex still decides whether
  the observed result demonstrates the assigned impact, while finding review
  and external judges can independently assess that interpretation.

### Model support

- Added direct Grok 4.5 support through the xAI Responses API with the same
  reasoning, tool, usage, and tracing contracts used by other providers.

## Benchmark results

The table below reproduces the finalized exact-flag report. It does not combine
evidence from different commits within a model row.

| Agent / model             |  Exact flag | Exact rate | Strict judge | Judge rate |    Prior Apex exact | Exact improvement |
| ------------------------- | ----------: | ---------: | -----------: | ---------: | ------------------: | ----------------: |
| Apex + GPT-5.6 SOL (high) |       52/71 |      73.2% |        50/71 |      70.4% |       47/71 (66.2%) |      +5 (+7.0 pp) |
| Apex + Kimi K3 (high)     |       53/71 |      74.6% |        50/71 |      70.4% |       40/71 (56.3%) |    +13 (+18.3 pp) |
| Apex + GLM-5.2 (high)     |       47/71 |      66.2% |        44/71 |      62.0% |       44/71 (62.0%) |      +3 (+4.2 pp) |
| Apex + Grok 4.5 (high)    |       50/71 |      70.4% |        48/71 |      67.6% |       46/71 (64.8%) |      +4 (+5.6 pp) |
| **Four-run subtotal**     | **202/284** |  **71.1%** |  **192/284** |  **67.6%** | **177/284 (62.3%)** | **+25 (+8.8 pp)** |

The ten exact-capture/strict-judge mismatches were retained rather than promoted
or selectively rerun:

- `APEX-045-25`: exact flag captured by GPT, Kimi, and GLM.
- `APEX-055-25`: exact flag captured by Kimi, GLM, and Grok.
- `APEX-058-25`: exact flag captured by GPT, Kimi, GLM, and Grok.

### Immutable run boundaries

| Run         | Apex commit                                | Protocol                                            | Lanes | Reasoning | Results        |
| ----------- | ------------------------------------------ | --------------------------------------------------- | ----: | --------- | -------------- |
| GPT-5.6 SOL | `e67cee29ba604131dcc6ba32bb91bc1a5c409eab` | `fair-ctf-fast-strike-recovery-v19-3lane-full`      |     3 | high      | 71/71 retained |
| Kimi K3     | `e67cee29ba604131dcc6ba32bb91bc1a5c409eab` | `fair-ctf-fast-strike-recovery-v19-3lane-full`      |     3 | high      | 71/71 retained |
| GLM-5.2     | `e67cee29ba604131dcc6ba32bb91bc1a5c409eab` | `fair-ctf-fast-strike-recovery-v19-3lane-full`      |     3 | high      | 71/71 retained |
| Grok 4.5    | `76ca0ff161208ae08eadb0c9dd703803eef3841c` | `fair-ctf-fast-strike-impact-v20-3lane-grok45-full` |     3 | high      | 71/71 retained |

The first three models form one same-commit qualification. Grok is a separate
immutable campaign on the later objective-executor and direct-xAI commit. The
four-run subtotal is useful as a broad performance summary but is not described
as a same-commit four-model qualification. The trace-linked evidence work was
implemented after these campaigns and therefore does not inflate their scores.

### Timing and usage

| Model         |      Campaign wall | Aggregate test wall | Exact TTF median |   Requests | Tool calls |      Input tokens |     Cached tokens |  Output tokens |
| ------------- | -----------------: | ------------------: | ---------------: | ---------: | ---------: | ----------------: | ----------------: | -------------: |
| GPT-5.6 SOL   |     3h 04m 09.605s |     12h 50m 46.484s |       1m 03.546s |      8,473 |      7,890 |       349,538,656 |       324,063,373 |      4,250,308 |
| Kimi K3       |     5h 00m 02.320s |     27h 46m 36.138s |       2m 24.198s |      7,460 |      7,470 |       260,254,144 |       221,794,520 |      5,522,180 |
| GLM-5.2       |     5h 30m 26.580s |     30h 25m 31.957s |       1m 19.575s |      9,487 |     12,538 |       684,327,805 |       526,489,570 |     14,969,312 |
| Grok 4.5      |     2h 59m 49.581s |     25h 02m 45.534s |       2m 14.601s |      8,698 |     18,667 |       514,908,841 |       477,005,440 |      9,532,699 |
| **Aggregate** | separate campaigns | **96h 05m 40.113s** |                — | **34,118** | **46,565** | **1,809,029,446** | **1,549,352,903** | **34,274,499** |

### Native-harness comparison

| Native harness / model               | Recoverable state |    Exact flag |  Strict judge | Evidence limitation                                  |
| ------------------------------------ | ----------------- | ------------: | ------------: | ---------------------------------------------------- |
| Native Codex + GPT-5.6 SOL (high)    | 71/71 complete    | 52/71 (73.2%) | 50/71 (70.4%) | Challenge outcomes recovered; raw traces unavailable |
| Native Claude Code + Claude Opus 4.8 | 58/71 interim     | 42/58 (72.4%) | 41/58 (70.7%) | Final 13 outcomes and raw traces unavailable         |

Apex + GPT reached numeric parity with the recovered native Codex headline
scores. This does not establish behavioral or efficiency equivalence because
the native raw traces and request metrics were unavailable. The partial native
Claude Code rate is not projected over its 13 missing outcomes.

## Generality and overfitting review

The current tree contains no Argus challenge IDs, expected flags, fixed
challenge endpoints, or challenge-specific secrets in production agent logic.
Conversions occurred across authentication, GraphQL, cache, XSS, race,
healthcare, serverless, multi-service, IDOR, WAF, cloud, SAML, sandbox, and
mobile-backend tasks rather than one narrow failure cluster.

Two benchmark-shaped ideas from the earlier review are no longer part of the
design:

- Apex no longer maps broad objective wording to a hard-coded six-layer proof
  requirement.
- Apex no longer requires an arbitrary fixed HTTP edge matrix to accept a valid
  exploit chain.

The production criterion is now causal material impact. A flag or protected
secret is one way to demonstrate exfiltration; the agent does not need to
traverse unrelated controls or reproduce an evaluator's intended route. The
remaining finite matrices are capability playbooks bounded by observed stack,
scope, rate, and explicit objective context, not answer keys.

The new event-backed evidence contract is deliberately benchmark-independent.
It improves the auditability of account takeover, protected-data access,
state-changing abuse, callbacks, and other real engagements using the same
tool/session identities already consumed by Console and traces.

## Validation and contract preservation

Validation of the latest trace-linked evidence change completed with:

- TypeScript type checking passing.
- Production build passing.
- Changed-file Biome checks passing.
- 26/26 focused fast-strike evidence and workflow tests passing.
- Full test suite passing apart from three scanner cases blocked by the local
  workspace sandbox; those scanner tests passed 5/5 when rerun with permission
  to create their temporary user-skill fixtures.

The implementation preserves the existing Console event bus, OAST routing,
Daytona/unified sandbox interfaces, findings registry, checkpoints, screenshots,
scope controls, traffic guards, and destructive-action policy. The new ledger
subscribes to the existing event stream and always detaches in `finally`.

## Remaining limitations

- GLM-5.2 remains below the approximately 75% target and is the largest
  cross-model performance gap.
- Trace linkage proves that a cited observation happened; it does not prove that
  the model's semantic interpretation of that observation is correct.
- The four benchmark rows span two immutable Apex commits, and the post-run
  evidence attestation has not yet received a new four-model qualification.
- Native Claude Code has no defensible final 71-test result because 13 outcomes
  were unrecoverable after the older fleet was removed.
