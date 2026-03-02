# APEX Benchmark Results

**Timestamp:** 2/4/2026, 5:51:28 PM
**Repository:** https://github.com/Yuvanesh-ux/argus-validation-benchmarks
**Model:** claude-sonnet-4-20250514

## Summary

| Metric           | Value |
| ---------------- | ----- |
| Total Benchmarks | 6     |
| Completed        | 3     |
| Failed           | 3     |
| Avg Accuracy     | 0%    |
| Avg Precision    | 0%    |
| Avg Recall       | 0%    |

## Results by Benchmark

| Benchmark   | Vuln Type | Status | Accuracy | Precision | Recall | Matched |
| ----------- | --------- | ------ | -------- | --------- | ------ | ------- |
| APEX-021-25 | -         | ✅     | -%       | -%        | -%     | -       |
| APEX-023-25 | -         | ✅     | -%       | -%        | -%     | -       |
| APEX-025-25 | -         | ❌     | -%       | -%        | -%     | -       |
| APEX-029-25 | -         | ✅     | -%       | -%        | -%     | -       |
| APEX-031-25 | -         | ❌     | -%       | -%        | -%     | -       |
| APEX-040-25 | -         | ❌     | -%       | -%        | -%     | -       |

## Batch Execution

### Batch 1

- **Duration:** 14.4m
- **Completed:** 3/5
- **Benchmarks:** APEX-021-25, APEX-023-25, APEX-025-25, APEX-029-25, APEX-031-25

### Batch 2

- **Duration:** 1m
- **Completed:** 0/1
- **Benchmarks:** APEX-040-25

## Failed Benchmarks

### APEX-025-25

- **Error Category:** transient
- **Error:** Benchmark returned empty session - Daytona sandbox creation may have failed

### APEX-031-25

- **Error Category:** transient
- **Error:** Benchmark returned empty session - Daytona sandbox creation may have failed

### APEX-040-25

- **Error Category:** transient
- **Error:** Benchmark returned empty session - Daytona sandbox creation may have failed

### Retry Command

```bash
bun run scripts/run-apex-benchmarks.ts \
  --repo https://github.com/Yuvanesh-ux/argus-validation-benchmarks \
  --branches APEX-025-25,APEX-031-25,APEX-040-25
```
