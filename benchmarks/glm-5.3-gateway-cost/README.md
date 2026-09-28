# GLM 5.3 Gateway Cost Benchmark

This benchmark compares the same GLM 5.3 model through OpenRouter and
Concentrate while leaving each gateway's default upstream routing enabled.
It reports billed spend and quality together: a cheap response that fails its
deterministic task is not a cost win.

## What is measured

The microbenchmark interleaves both gateways over five cases:

1. exact-answer reasoning
2. structured extraction
3. a two-step tool call
4. security analysis with known findings
5. repeated long-context retrieval for cold/warm cache behavior

Each sample records:

- provider-reported billed cost
- cost normalized to one captured GLM 5.3 list-rate snapshot
- served model and route
- input, output, reasoning, cache-read, and cache-write tokens
- time to first token, total latency, and output throughput
- deterministic pass/fail status

The production-shaped layer can run the same Argus branches through each
gateway in Fast Strike mode. The separate LLM comparison scorer is disabled so
evaluator spend does not contaminate the gateway totals; flag capture is the
deterministic quality gate.

## Cost model

At the time this benchmark was authored, both gateway catalogs listed the
Z.ai route at:

| Bucket                      | USD / 1M tokens |
| --------------------------- | --------------: |
| Input                       |           $1.40 |
| Output, including reasoning |           $4.40 |
| Cache read                  |           $0.26 |
| Cache write                 |           $0.00 |

The runner snapshots current rates from OpenRouter's public model catalog
before every run. It then presents two different cost views:

1. **Provider-billed inference** is the exact response charge. This is the
   amount used by the spend guard.
2. **Reference-rate cost** applies the same captured rates to both token
   streams. This isolates token efficiency from route-specific discounts.

Gateway funding fees are separate from per-request inference:

- Concentrate publishes no platform or card fee.
- OpenRouter publishes a 5.5% credit-purchase fee with a $0.80 minimum.

The generated report shows OpenRouter cash-cost sensitivity for $10, $100,
and $1,000 credit purchases rather than pretending the minimum fee can be
allocated to one request without a purchase-size assumption.

Sources:

- [OpenRouter pricing](https://openrouter.ai/pricing)
- [OpenRouter usage accounting](https://openrouter.ai/docs/cookbook/administration/usage-accounting)
- [OpenRouter GLM 5.3](https://openrouter.ai/z-ai/glm-5.3)
- [Concentrate pricing](https://concentrate.ai/pricing)
- [Concentrate GLM 5.3](https://concentrate.ai/models/glm-5.3)

## Credentials

Both `OPENROUTER_API_KEY` and `CONCENTRATE_API_KEY` are required. The scripts
also understand SST's `SST_RESOURCE_OpenrouterApiKey` and
`SST_RESOURCE_ConcentrateApiKey` envelopes, so they can run inside
`bun sst shell` without printing or copying secret values.

An empty SST secret fails preflight. It is never sent as an API key.

## Run

From the Console repository root:

```bash
# Two-call paid smoke test, capped at $1.
bun sst shell -- bash -lc \
  'cd packages/apex && bun run scripts/run-glm-cost-bench.ts \
    --smoke \
    --output ~/.pensar/benchmark-reports/glm-5.3-gateways'

# Five cases × three repetitions × two gateways, capped at $10.
bun sst shell -- bash -lc \
  'cd packages/apex && bun run scripts/run-glm-cost-bench.ts \
    --repetitions 3 \
    --budget 10 \
    --output ~/.pensar/benchmark-reports/glm-5.3-gateways'
```

Run the matched Argus branches in local Fast Strike mode. The cost ceiling is
applied independently to every branch:

```bash
bun sst shell -- bash -lc \
  'cd packages/apex && bun run scripts/run-benchmarks.ts \
    --branches APEX-050-25,APEX-051-25,APEX-052-25,APEX-053-25,APEX-054-25,APEX-055-25 \
    --model z-ai/glm-5.3 \
    --mode local \
    --fast-strike \
    --track-provider-cost \
    --max-provider-cost 25 \
    --no-comparison \
    --output ~/.pensar/benchmark-reports/glm-5.3-argus/openrouter'

bun sst shell -- bash -lc \
  'cd packages/apex && bun run scripts/run-benchmarks.ts \
    --branches APEX-050-25,APEX-051-25,APEX-052-25,APEX-053-25,APEX-054-25,APEX-055-25 \
    --model concentrate:glm-5.3 \
    --mode local \
    --fast-strike \
    --track-provider-cost \
    --max-provider-cost 25 \
    --no-comparison \
    --output ~/.pensar/benchmark-reports/glm-5.3-argus/concentrate'
```

The twelve Argus runs have a maximum provider-billed spend of $300. Argus checks
the budget after every completed model step and aborts before starting another
step.

## Combine the reports

```bash
bun run scripts/compare-argus-provider-results.ts \
  --openrouter <openrouter-benchmark-results.json> \
  --concentrate <concentrate-benchmark-results.json> \
  --output <comparison-directory> \
  --per-run-budget 25
```

The combined JSON retains both Argus suite results. The Markdown report includes
per-branch status, flag capture, findings, billed and normalized cost, route
distribution, duration, token usage, cost per captured flag, and combined spend.

## Interpretation limits

- Default routing intentionally permits different hosts and quantizations.
  Route distribution is therefore part of the result, not noise to discard.
- Provider availability, discounts, and route quality change over time.
  Re-run before making a purchasing decision.
- Three micro repetitions characterize a pilot, not a long-term latency SLO.
- Six Argus targets improve coverage but still do not establish a broad
  security-quality ranking.
- Reasoning is billed as output. A separate reasoning count is shown only when
  the serving route reports it.
