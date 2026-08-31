# PDR-008: Provider-attempt envelope

## Context

Apex reports token usage through several completed-step and telemetry
callbacks. Provider fields are not uniform: Anthropic's native
`input_tokens` is uncached, while the AI SDK's `usage.inputTokens` is
inclusive of cache. Missing cache counters were coerced to zero
([#1002](https://github.com/pensarai/apex/pull/1002)), so a consumer
cannot tell a reported zero from omitted data. Local telemetry is not
a billing ledger, but it was easy to treat it as one.

## Decision

A versioned, provider-neutral `ProviderAttemptEnvelope` represents one
physical inference attempt. Token categories are finite non-negative
integers when known and explicit `null` when the provider did not
report them. The contract contains no money, rate, customer, or
provider-account fields. Identity (`atm_…` / `idk_…`) is allocated
before the provider request. Existing `onUsage` / `onCacheMetrics` /
`onStepFinish` consumers keep their #1002 zero-filling projection until
they migrate.

## Rationale

**Unknown is not zero.** Coercing omitted cache fields to `0` makes
"this route never caches" indistinguishable from "the adapter dropped
the split" — the silent Bedrock failure [#943](https://github.com/pensarai/apex/pull/943)
fixed. Downstream pricing that treats every input count the same will
double-count cache.

**Physical attempt, not a ledger.** An envelope is one HTTP/SDK call,
including retries as a lineage of new identities. Cost, rate cards, and
customer accounts belong elsewhere. Keeping money out of this contract
prevents local telemetry from becoming an accidental source of truth
for billing.

**Provider-neutral names.** Transports adapt native shapes into
inclusive / uncached / cache-read / cache-write / output. The envelope
never exposes Anthropic- or OpenAI-specific field names.

## Alternatives considered

- **Keep extending `UsageCallbackContext`** — rejected. It cannot
  represent unknown vs zero without breaking #1002 consumers, and it
  has no attempt identity or lifecycle.
- **Put dollars on the envelope** — rejected. Pricing catalogs and
  provider invoices change independently of physical token counts.
- **Treat missing cache as zero at the adapter** — rejected. That is
  the current bug. Derive a field only when the other identity inputs
  are known.

## Consequences

- ✅ Consumers can trust token fields or see that they are unknown
- ✅ Retry lineage and root/child attribution have a single shape
- ✅ Existing completed-step callbacks stay valid via projection
- ⚠️ Live emission at every inference entry point is a follow-up
  ([#1013](https://github.com/pensarai/apex/issues/1013))
- ⚠️ Adapters must be fixture-tested per transport; a new provider
  route needs a new adapter plus fixtures
