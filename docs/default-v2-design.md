# Default v2: target harness design

Status: proposed architecture and acceptance criteria, 2026-11-11. This document
defines the intended behavior; it does not claim the current branch implements
it or that the design has demonstrated a performance improvement.

## Objective

Apex is a capable conversational agent specialized for security research. It
follows the user's objective, evaluates hints, develops evidence, and pursues
the requested depth of investigation. The model chooses the research strategy.
The harness supplies reliable execution, relevant context, and enforced scope.

Design against the documented behavior of frontier harnesses first. Existing
Apex code earns reuse by satisfying these contracts. Similar component names,
historical architecture decisions, or the presence of an API are insufficient.

## Architecture

```mermaid
flowchart TD
    Clients["TUI / CLI / API / eval runner"] --> Session["Session: messages, turns, events, evidence references"]
    Session --> Loop["Model chooses an action or a response"]
    Loop --> Provider["Provider adapter: native model semantics"]
    Provider --> Loop
    Loop --> Tools["Capability execution and policy enforcement"]
    Tools --> Environment["Local or sandbox execution environment"]
    Environment --> Results["Results, job handles, retained artifacts"]
    Results --> Session
```

These are ownership boundaries, not a requirement for new services, packages,
or an interface hierarchy. Start with one in-process implementation and the
execution adapters the product actually needs.

## Decisions

### 1. One adaptive primary agent owns the investigation

The primary model interprets the request, chooses experiments, revises its
explanation, and decides what evidence is still needed. It can move between
source inspection, protocol experiments, coding, reproduction, and explanation
without changing agent personas or satisfying stage transitions.

Security instructions specify evidence standards, scope, and completion
expectations. They do not prescribe a universal methodology. A request to
demonstrate impact requires a demonstrated result or a precise account of the
remaining blocker; a question or triage request has its own appropriate depth.
A failed experimental setup remains inconclusive. A user hint is a lead to
evaluate, and later corrections update the active assignment.

Delegation is an exception for an explicitly requested or clearly beneficial
independent task. The main investigation stays with its accumulated context.
This is our design choice, not a claim that frontier harnesses have eliminated
subagents. Independent tool calls and scripts can still run concurrently.

Claude Code documents a loop that adapts to the request and previous results,
with extensions layered over its core tools. [Claude Code architecture](https://code.claude.com/docs/en/how-claude-code-works).

### 2. A session owns the loop across every interface

One owner assembles model input and manages messages, tool results, pending
execution, approvals, cancellation, compaction, and completion. Clients submit
user input and render events. An environment provides execution capabilities
and actual runtime facts; it does not select a pentest methodology.

A reconnect, new user turn, or change of interface must not silently create a
different research policy. Separate turn completion, task outcome, and process
termination. An exhausted budget or failed tool must not be recorded as a
verified result.

Codex exposes shared conversation and execution behavior to product clients
through its app-server. This motivates the ownership boundary; it does not
require Apex to reproduce that transport. [Codex platform](https://developers.openai.com/blog/codex-as-a-platform),
[app-server](https://developers.openai.com/codex/app-server).

### 3. Preserve the capabilities of the selected model

Provider adapters must preserve supported reasoning items, tool-call identities,
ordering, output formats, and requested reasoning settings. Do not reduce all
providers to the smallest common message format or silently change the model
doing the investigation. Treat opaque provider state as opaque.

For supported OpenAI models, use append-only conversation updates and the
documented continuation and compaction mechanisms. Shorten a large tool result
before its first inclusion in model input, retaining the full artifact. Do not
quietly rewrite already-consumed history on each subsequent step. Other
providers require their own documented semantics and conformance tests.

OpenAI documents that reasoning items must accompany tool results and that
prefix edits can discard subsequent reasoning. Native OpenAI compaction has
different preservation behavior from arbitrary history rewriting. This makes
history handling a capability requirement, beyond a token-cost optimization.
[Reasoning continuation](https://developers.openai.com/api/docs/guides/reasoning#keeping-reasoning-items-in-context),
[prefix preservation](https://developers.openai.com/api/docs/guides/preserved-reasoning).

### 4. Expose a small, clear set of composable capabilities

Make file inspection and editing, search, command execution, relevant network
or browser interaction, artifact retrieval, and capability discovery easy to
use. Each operation states its real effects, state ownership, and result
contract. Additional security and workspace capabilities are discoverable.

Discovery must respect provider history semantics: use supported additive tool
updates or a stable discovery/invocation surface. Avoid changing previous tool
definitions just to reduce the currently displayed catalog. Permission checks
apply at invocation, including programmatic and discovered calls.

Recording evidence, generating analysis, delegating work, and publishing a
finding are distinguishable operations. If an operation includes validation or
additional execution, its contract makes that explicit. Preserve the evidence
requirements for publishing confirmed findings.

Anthropic recommends unambiguous tools with little overlap and retrieving
context when needed. Those recommendations motivate the capability surface;
the exact Apex tool set remains an evaluation question.
[Context engineering](https://www.anthropic.com/research/effective-context-engineering-for-ai-agents).

### 5. Preserve a useful investigation workspace

Keep scripts, captured requests, source references, experimental results, and
working reproductions available throughout the session. Return concise results
with retrievable references and enough surrounding evidence to interpret them.
Preserve exact security-relevant bytes when an experiment depends on them.

The model can keep research notes when useful. Compaction preserves the current
objective, corrections, constraints, unresolved leads, successful primitives,
and evidence references. Distinguish user statements, observed results, and
model hypotheses. Do not introduce a mandatory per-action ledger or a second
model that decides the research strategy.

Claude Code documents on-demand skills and tool definitions, alongside
compaction and persistent project instructions. These mechanisms support
selective context loading; they do not guarantee that every important clue
survives. [Claude Code context](https://code.claude.com/docs/en/how-claude-code-works#the-context-window).

### 6. Make sustained experiments observable and controllable

An operation that outlives a tool response returns an owned job or session
handle. The model can inspect partial output, continue where supported, cancel,
and retrieve final artifacts. Execution state such as working directory,
environment, authentication, and process lifetime has explicit semantics.

Enforce permission, time, concurrency, and resource limits in execution code.
Expose budget exhaustion accurately. Do not equate a long investigation with
failure or force a hypothesis pivot after an arbitrary number of negatives.
Research depth is judged by the user's objective and the evidence obtained.

## Observable acceptance criteria

| Desired behavior                                                  | Invariant and enforcement                                                                                                                          | Verification                                                                                                                                              |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Apex follows a specific research request and later corrections.   | User messages remain authoritative; tool content cannot change scope. Session assembly and capability policy own these boundaries.                 | Multi-turn tasks with precise hints, corrections, and prohibited broad scans; test before and after compaction.                                           |
| Apex investigates a promising lead to the requested depth.        | A finding or intermediate primitive does not automatically complete an impact objective. Outcome reporting distinguishes evidence from hypotheses. | Held-out source-assisted and black-box tasks requiring a reproduction and independently verified impact; include failed setup and negative-control cases. |
| Apex challenges an incorrect hint with evidence.                  | A user's hypothesis is not automatically stored as an observed fact.                                                                               | Paired tasks with useful, ambiguous, and misleading hints; score outcome and supporting evidence.                                                         |
| Model state survives ordinary tool round trips.                   | Provider-owned state and item ordering are preserved through the supported adapter path.                                                           | Request-capture conformance tests for repeated tool calls, new user input, resume, tool discovery, and compaction; verify supported native settings.      |
| TUI, CLI, and API use the same session behavior.                  | Clients do not inject independent workflow policy; environments report facts and execute.                                                          | Run the same scripted conversation through each entry point with deterministic tools; compare model-visible semantics.                                    |
| A long experiment remains inspectable and has a truthful outcome. | Every live job has an owner; cancellation and failure cannot produce fabricated success.                                                           | Partial output, timeout, cancellation, reconnect, and final-artifact integration checks against actual execution adapters.                                |

Behavioral acceptance requires real-model evaluations. Structural tests prove
contracts, not research quality. Use existing evaluation infrastructure where
it meets the test requirements; adding another evaluation platform is outside
this design.

Compare matched model, reasoning settings, task, environment, and budget where
possible. Native Codex and Claude Code runs are product baselines. Cross-model
comparisons do not isolate harness effects. Repeat tasks, retain denominators,
and hold out tasks from design work. Do not grade a single prescribed tool
sequence.

The primary measures are verified task completion and demonstrated security
impact with false-positive control. Also measure hint use, unwanted workflow
launches, loss of corrections after compaction, time, cost, and unfinished
viable leads. More tool calls, fewer tool calls, or more findings alone are not
success criteria.

## Delivery through the default-v2 stack

Keep default-v2 runnable as an opt-in path throughout delivery. The existing
mode selection is the development entry point, not evidence that the design is
complete. Each behavioral change ships with its relevant acceptance cases.

1. Establish the session and provider-state contract, including client parity,
   continuation, and compaction. Replace incompatible context handling where
   necessary. Keep pure ownership refactors separate from behavioral changes.
2. Deliver the capability surface and execution lifecycle: explicit tool
   effects, supported discovery, retained artifacts, and owned long-running
   operations. Preserve invocation policy across every path.
3. Calibrate the security-specific instructions and optional expertise against
   held-out deep-research and conversational tasks. Remove policies that do
   not improve outcomes. Publish the comparison evidence before broad rollout.

No automatic hypothesis-ranking service, mandatory recon checklist, fixed
research phases, or additional orchestration layer is part of this design.
Add such machinery only if controlled evidence demonstrates a need that the
primary model and existing execution primitives cannot satisfy.
