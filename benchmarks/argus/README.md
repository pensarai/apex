# Argus Benchmark Results

Argus is a 60-benchmark validation suite for evaluating AI-powered penetration testing tools. Each benchmark is a self-contained Docker Compose environment with intentionally planted vulnerabilities and a defined set of expected findings.

**Benchmark targets:** [pensarai/argus-validation-benchmarks](https://github.com/pensarai/argus-validation-benchmarks)

## Headline Numbers

| Metric | Value |
|--------|-------|
| Total benchmarks | 60 |
| Completed with scored results | 55 |
| 100% recall (all expected vulns found) | 34 |
| Failed to run (infra issues) | 4 |
| Total spend (all runs, Feb 2-13) | ~$1,190 |
| Models used | Claude Sonnet 4 (001-023), Claude Haiku 4.5 (025-060) |

## Benchmark Categories

**Single-vulnerability targets (001-040):** Each app has one primary vulnerability class (SSRF, SQLi, XSS, JWT confusion, etc.). Tests whether the tool can identify the specific vulnerability among noise.

**Intermediate targets (023, 030, 034, 040):** Multiple vulnerabilities or more complex exploitation paths.

**Multi-step attack chains (041-060):** Multi-service Docker environments requiring sequential vulnerability exploitation. No single vulnerability yields the flag; the complete chain must be executed. Designed after APEX-040 "The Gauntlet" and influenced by PACEBench methodology.

## How to Read the Results

### CSV Columns (`consolidated-results.csv`)

| Column | Description |
|--------|-------------|
| Benchmark | ID (e.g. APEX-001-25) |
| Vulnerability Type | Primary vulnerability class |
| Model | LLM used (sonnet or haiku) |
| Status | success, missed, or failed |
| Precision (%) | True positives / total reported findings |
| Recall (%) | True positives / total expected findings |
| Expected Found | Whether the primary vulnerability was identified |
| Total Actual | Total findings reported by the agent |
| Run Date | When the benchmark was executed |
| Notes | Qualitative notes on what was found/missed |

### Scoring Methodology

Each benchmark has a set of **expected findings** defined in its branch. After a run, an LLM-based scorer compares the agent's findings against expected findings using semantic matching (not exact string comparison). A finding is "matched" if it describes the same vulnerability class at the same location, even if the title or description differs.

- **Recall** = matched expected findings / total expected findings
- **Precision** = matched expected findings / total actual findings reported
- **Status = "success"** means at least one expected finding was matched
- **Status = "missed"** means the agent ran to completion but matched zero expected findings
- **Status = "failed"** means the run crashed or couldn't complete

## Directory Structure

```
argus/
├── README.md                    # This file
├── consolidated-results.csv     # Master CSV: all 60 benchmarks with scores
├── consolidated-report.md       # Full analysis report (Feb 2-13 runs)
├── comparison-feb20.md          # Feb 20 Haiku re-run comparison
├── cost-breakdown.md            # Detailed per-run cost and token data
├── chain-benchmarks-design.md   # Design doc for multi-step chains (041-060)
└── runs/
    ├── consolidated/            # 59 successful runs (Feb 2-13) with full detail
    │   └── apex-run-*/          # Per-run: summary, comparison results, token metrics
    ├── feb18-20-reruns/         # 52 raw JSON reports from Feb 18-20 re-runs
    └── feb20-rerun/
        ├── README.md            # What the Feb 20 re-run covers
        └── results.json         # Aggregated JSON (12 successful benchmarks)
```

## Key Files

- **[consolidated-results.csv](./consolidated-results.csv)** — Start here. One row per benchmark, sortable/filterable.
- **[consolidated-report.md](./consolidated-report.md)** — Detailed narrative analysis with per-benchmark breakdowns.
- **[comparison-feb20.md](./comparison-feb20.md)** — Sonnet vs Haiku comparison on a subset of benchmarks.
- **[cost-breakdown.md](./cost-breakdown.md)** — Token counts and dollar costs for tracked runs.
- **[chain-benchmarks-design.md](./chain-benchmarks-design.md)** — Design document for the 20 multi-step chain benchmarks (APEX-041 through APEX-060).
- **[runs/consolidated/](./runs/consolidated/)** — Full run data for all 59 successful runs, including per-benchmark comparison results, token metrics, and scoring rationale.
- **[runs/feb18-20-reruns/](./runs/feb18-20-reruns/)** — Raw JSON reports from 52 individual re-runs (Feb 18-20), with detailed finding-level comparison data.
