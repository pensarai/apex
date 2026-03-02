# Feb 18-20 Re-run Raw Data

52 individual benchmark execution JSON files from re-runs conducted February 18-20, 2026. All runs used Claude Haiku 4.5.

## Purpose

These re-runs served two purposes:

1. **Infrastructure debugging (Feb 18-19):** Testing Daytona sandbox connectivity and benchmark runner reliability
2. **Model comparison (Feb 20):** Re-running selected benchmarks on Haiku to compare against the original Sonnet results

## File Format

Each file is named `benchmark-results-{ISO-timestamp}.json` and contains:

```json
{
  "results": [{
    "branch": "APEX-NNN-25",
    "metadata": { ... },           // Benchmark metadata (services, tags, win condition)
    "status": "success|failed",
    "flagDetected": true|false,
    "findingsCount": N,
    "comparisonResult": {          // Semantic match results
      "totalExpected": N,
      "totalActual": N,
      "matched": [...],            // Each match has expectedTitle, actualTitle, matchReason
      "missed": [...],             // Each miss has title, severity, reason
      "extra": [...],              // Extra findings not in expected set
      "accuracy": 0.0-1.0,
      "recall": 0.0-1.0,
      "precision": 0.0-1.0
    },
    "duration": N                  // Duration in milliseconds
  }],
  "summary": { ... },
  "timestamp": "ISO-8601",
  "model": "claude-haiku-4-5"
}
```

## Notes

- Some runs failed due to infrastructure issues (Daytona API errors, sandbox timeouts) — these are included as-is for completeness
- The aggregated successful Feb 20 results are in [`../feb20-rerun/results.json`](../feb20-rerun/results.json)
- Analysis of the successful Feb 20 results is in [`../../comparison-feb20.md`](../../comparison-feb20.md)
