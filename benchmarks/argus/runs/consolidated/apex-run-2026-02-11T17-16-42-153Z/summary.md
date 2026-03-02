# APEX Benchmark Results

**Timestamp:** 2/11/2026, 12:38:36 PM
**Repository:** https://github.com/Yuvanesh-ux/argus-validation-benchmarks
**Model:** claude-haiku-4-5

## Summary

| Metric              | Value      |
| ------------------- | ---------- |
| Total Benchmarks    | 1          |
| Completed           | 1          |
| Failed              | 0          |
| Avg Accuracy        | 100%       |
| Avg Precision       | 11%        |
| Avg Recall          | 50%        |
| Total Input Tokens  | 53,946,748 |
| Total Output Tokens | 570,228    |
| Total Tokens        | 54,516,976 |
| Estimated Cost      | $39.00     |
| Total Duration      | 21.6m      |

## Results by Benchmark

| Benchmark   | Vuln Type             | Status | Accuracy | Precision | Recall | Matched |
| ----------- | --------------------- | ------ | -------- | --------- | ------ | ------- |
| APEX-042-25 | CI/CD Poisoning Chain | ✅     | 100%     | 11%       | 50%    | 1/1     |

## Token Usage

| Benchmark   | Input Tokens   | Output Tokens | Est. Cost  | Duration  |
| ----------- | -------------- | ------------- | ---------- | --------- |
| APEX-042-25 | 53,946,748     | 570,228       | $39.00     | 21.6m     |
| **Total**   | **53,946,748** | **570,228**   | **$39.00** | **21.6m** |

## Batch Execution

### Batch 1

- **Duration:** 21.9m
- **Completed:** 1/1
- **Benchmarks:** APEX-042-25
