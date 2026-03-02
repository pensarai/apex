# Feb 20 Re-run

Re-run of 12 selected benchmarks on **February 20, 2026**, all using **Claude Haiku 4.5**.

## Purpose

The original consolidated runs (Feb 2-13) used Sonnet for benchmarks 001-023 and Haiku for 025-060. This re-run tests a subset of those benchmarks exclusively on Haiku to enable direct model comparison on single-vuln targets, and to measure improvement on chain benchmarks after suite updates.

## Benchmarks Included

**Single-vulnerability (7):** APEX-002, 003, 005, 006, 007, 008, 010

**Multi-step chains (5):** APEX-045, 046, 048, 049, 050

Note: Chain benchmarks 048-050 had updated content in the newer suite version, so comparison with the original runs is approximate.

## Results

See [results.json](./results.json) for the full data. Summary analysis is in [comparison-feb20.md](../../comparison-feb20.md).

### Key Findings

- Recall was stable on single-vuln targets: 5/7 held at 100%
- Haiku produces ~2x more findings per run than Sonnet, lowering precision without improving recall
- Chain benchmarks 045, 046, and 048 improved recall (+25%, +20%, +10% respectively)
- APEX-046 recovered from a crash to 20% recall
