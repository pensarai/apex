# PDR-008: Selector-driven white-box reconnaissance

## Context

White-box reconnaissance must account for an entire repository while producing
source-backed application and interface records. A first implementation divided
all analyzable files into agent shards. On a large repository this created 7,724
planned shards, ran hundreds of long-lived agents, and consumed more than 100
million input tokens without producing an inventory.

PDR-003's swarm architecture is appropriate for independent pentest targets and
objectives. Repository coverage is different: every worker contributes to one
global accounting invariant, so unconstrained exploration and nested fan-out
multiply cost without establishing completeness.

## Decision

`/whitebox-recon` uses a selector-driven map-reduce workflow:

1. Code inventories and hashes the repository.
2. One bounded model call proposes deployable applications, configuration
   ownership prefixes, and supplemental literal selectors.
3. Code extracts formal schemas and literal configuration identities, then
   executes built-in and proposed selectors over every eligible file.
4. Repeated deterministic facts are persisted directly; only the finite
   semantic candidate ledger is packed into bounded, dependency-connected
   evidence bundles.
5. Up to four one-shot structured model calls run concurrently. They have no
   tools and cannot spawn more work.
6. A single controller validates and persists results. One reducer call is used
   only when canonical application conflicts exist.
7. Hard call, token, bundle, and duration budgets return an explicit incomplete
   result rather than silently skipping work.

The workflow is a new implementation and does not use or fall back to Surface or
the legacy white-box attack-surface workflow.

## Rationale

Deterministic selectors give the run a finite, inspectable coverage boundary.
Formal GraphQL, protobuf, OpenAPI, host, port, URL, and resource declarations do
not spend model tokens when code can extract them exactly.
One-shot workers receive only relevant evidence, preventing repository reads and
tool results from accumulating across model turns. A single writer avoids shared
mutable state. Content-addressed batch artifacts make interruption resumable and
unchanged reruns inexpensive.

## Alternatives considered

- **One agent browsing the repository** — rejected because it has no objective
  coverage boundary and its context grows with exploration.
- **One worker per raw file shard** — rejected because repository size directly
  becomes model-call count even when most files contain no interfaces.
- **Nested or manager-driven swarms** — rejected because this workflow has shared
  global state and requires deterministic accounting.
- **Deterministic framework parsers only** — rejected as the sole approach because
  custom wrappers and unsupported frameworks require bounded semantic judgment.

## Consequences

- ✅ Every eligible file receives a deterministic selector disposition.
- ✅ Model-call and token use have enforceable upper bounds.
- ✅ Every candidate and accepted record has an explicit disposition.
- ✅ Completed bundles survive interruption and are reusable.
- ⚠️ Selector recall becomes the primary coverage risk and must be measured on
  pinned ground-truth repositories.
- ⚠️ Runs that exceed a safety limit return partial, explicitly incomplete output.
