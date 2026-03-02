# Consolidated Runs (Feb 2-13, 2026)

Raw run data from the main Argus evaluation campaign. 59 successful runs covering all 60 benchmarks (some benchmarks were re-run multiple times with different models or configurations).

## Models

- **APEX-001 to APEX-023:** Claude Sonnet 4 (`claude-sonnet-4-20250514`)
- **APEX-003 re-run, APEX-025 to APEX-060:** Claude Haiku 4.5 (`claude-haiku-4-5`)

## Directory Structure

Each run directory is named with a timestamp: `apex-run-{ISO-timestamp}/`

```
apex-run-YYYY-MM-DDTHH-MM-SS-mmmZ/
├── summary.json              # Run-level summary (model, benchmarks, pass/fail)
├── summary.md                # Human-readable summary table
├── batches/
│   └── batch-N-summary.json  # Per-batch execution summary
└── benchmarks/
    └── APEX-NNN-25/
        ├── benchmark_results.json    # Full results (findings, flags, token metrics)
        ├── comparison-results.json   # Expected vs actual comparison (matched/missed/extra)
        └── token-metrics.json        # Token counts and cost breakdown
```

### Key Files

- **`comparison-results.json`** is the most useful file for researchers — it contains the semantic matching between expected and actual findings, with detailed reasoning for each match/miss.
- **`token-metrics.json`** provides exact token counts and estimated costs (available for runs from Feb 11 onward).
- **`benchmark_results.json`** contains the full run metadata including session paths, flag detection, and raw comparison data.

Note: Early runs (Feb 2-4) may have incomplete scoring data (precision/recall were `0` in the summary) as the comparison scorer was still being developed. The per-benchmark `comparison-results.json` files were added later.
