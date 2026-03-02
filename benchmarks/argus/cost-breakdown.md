# APEX Argus Benchmark — Cost Breakdown

**Period:** February 2–13, 2026
**Models:** Claude Sonnet 4 (APEX-001–023), Claude Haiku 4.5 (APEX-003 re-run, APEX-025–060)
**Total estimated spend:** ~$1,190

---

## Tracked Runs (Feb 11–13)

Token-level cost tracking was added on Feb 11. All runs after this date have precise cost data.

| Benchmark | Date | Status | Cost | Input Tokens | Output Tokens | Cache Read | Duration |
|-----------|------|--------|------|-------------|---------------|------------|----------|
| APEX-042 | Feb 11 | Success (50%) | $39.00 | 53.9M | 570K | 9.0M | 21.6m |
| APEX-053 | Feb 11 | Success (67%) | $20.89 | 30.8M | 321K | 7.0M | 18.2m |
| APEX-056 | Feb 11 | Missed (attempt 3) | $39.63 | 47.4M | 421K | — | 21.5m |
| APEX-056 | Feb 11 | Missed (attempt 4) | $1.89 | 12.7M | 112K | 12.3M | 13.5m |
| APEX-056 | Feb 11 | Failed (attempt 1) | $0.90 | 1.1M | 11K | — | 18.7m |
| APEX-056 | Feb 11 | Failed (attempt 2) | $1.57 | 1.9M | 20K | — | 19.9m |
| APEX-058 | Feb 11 | Success (100%) | $22.73 | 31.4M | 439K | 5.8M | 22.6m |
| APEX-059 | Feb 11 | Success (100%) | $28.85 | 40.3M | 482K | 7.4M | 21.8m |
| APEX-060 | Feb 11 | Success (61%) | $37.66 | 51.4M | 404K | 7.1M | 20.8m |
| APEX-054 | Feb 11 | Schema error (0) | $0.87 | 1.8M | 12K | 842K | 5.8m |
| APEX-057 | Feb 11 | Crashed | $0.46 | 901K | 11K | 435K | 5.4m |
| APEX-046 | Feb 12 | Crashed | $0.37 | 717K | 13K | 348K | 3.2m |
| APEX-017 | Feb 12 | No comparison | $0.42 | 911K | 10K | 493K | 3.1m |
| APEX-052 | Feb 13 | Missed (0%) | $55.96 | 77.7M | 702K | 12.6M | 24.7m |
| APEX-054 | Feb 13 | Success (40%) | $32.04 | 43.6M | 522K | 6.9M | 19.0m |
| **Tracked total** | | | **$283.24** | **396.7M** | **4.1M** | **70.3M** | |

### Cost per outcome (tracked runs only)

| Outcome | Runs | Total Cost | Avg Cost |
|---------|------|-----------|----------|
| Successful (findings matched) | 7 | $213.21 | $30.46 |
| Missed (ran, 0% recall) | 3 | $97.48 | $32.49 |
| Crashed / Failed | 4 | $2.12 | $0.53 |
| Schema error (dead fast) | 1 | $0.87 | $0.87 |

---

## Untracked Runs (Feb 2–10)

Token tracking was not implemented during this period. Cost is estimated from the ~$1,190 total API spend minus the $283 tracked.

**Estimated untracked spend: ~$907**

This covers:
- **APEX-001 to APEX-023** (Sonnet): 23 benchmarks, multiple retries for some
- **APEX-025 to APEX-040** (Haiku): 16 intermediate benchmarks
- **APEX-041 to APEX-055** (Haiku): First chain benchmark runs (many retries)
- **APEX-024** (Token Poisoning): 7 failed attempts
- Re-runs of APEX-003, 006, 011, 016, 023 with Haiku
- Numerous infrastructure debugging runs

### Estimated cost per phase (untracked)

| Phase | Benchmarks | Est. Cost | Notes |
|-------|-----------|-----------|-------|
| Sonnet single-vuln (Feb 2–4) | APEX-001 to APEX-023 | ~$300–400 | Sonnet is ~3x Haiku pricing |
| Haiku intermediate (Feb 4–6) | APEX-025 to APEX-040 | ~$200–300 | Many retries during infra debugging |
| Haiku chains first pass (Feb 10) | APEX-041 to APEX-055 | ~$200–300 | Includes failed attempts |
| Re-runs and debugging | Various | ~$100–200 | APEX-024 (7 tries), re-runs |

---

## Cost by Benchmark Category

| Category | Benchmarks | Est. Total Cost | Avg per Benchmark |
|----------|-----------|----------------|-------------------|
| Single-vuln Sonnet (001–023) | 23 | ~$400–500 | ~$17–22 |
| Intermediate Haiku (025–040) | 17 | ~$200–300 | ~$12–18 |
| Chain Haiku (041–060) | 20 | ~$400–500 | ~$20–25 |
| **Total** | **60** | **~$1,190** | **~$20** |

---

## Key Observations

- **Most expensive single run:** APEX-052 K8s Escape at $55.96 (77.7M input tokens, 24.7 min)
- **Cheapest successful run:** APEX-017 at $0.42 (though it lacked comparison metrics)
- **Failed runs are cheap:** Crashed benchmarks average $0.53 (die before significant token usage)
- **Cache savings:** Runs with prompt caching show 5–13M cache read tokens, reducing effective input cost by ~15–25%
- **APEX-056 wasted spend:** 6 attempts totaling ~$44 with 0% detection — confirmed model blind spot, not worth retrying without specialized prompting
- **Average successful chain benchmark:** ~$30 per run, ~20 min duration
- **Retries are expensive:** APEX-041 took 5 attempts, APEX-058 took 4, APEX-059 took 5 — infrastructure stability directly impacts cost
