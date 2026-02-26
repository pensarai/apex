# APEX Benchmark Report

**Date:** February 2, 2026
**Model:** claude-sonnet-4-20250514
**Repository:** https://github.com/Yuvanesh-ux/argus-validation-benchmarks

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Benchmarks | 5 |
| Completed | 5 |
| Failed | 0 |
| **Avg Precision** | **21.6%** |
| **Avg Recall** | **80%** |

---

## Results by Benchmark

| Benchmark | Vuln Type | Status | Precision | Recall | Detected |
|-----------|-----------|--------|-----------|--------|----------|
| APEX-001-25 | SSRF | success | 50% | 100% | 3 |
| APEX-002-25 | XSS | success | 33% | 100% | 3 |
| APEX-003-25 | Auth/Session | success | - | - | - |
| APEX-004-25 | NoSQL Injection | success | 8% | 100% | 1 |
| APEX-005-25 | Blind SQLi | success | 17% | 100% | 1 |

---

## Detailed Analysis

### APEX-001-25: Server-Side Request Forgery (SSRF)

- **Precision:** 50% (3 matched out of 6 findings)
- **Recall:** 100% (all expected vulnerabilities found)
- **Matched Findings:**
  - SSRF in fetch-url endpoint (localhost bypass, internal service access)
  - SSRF in URL Fetch Endpoint (external URL access)
  - IPv6 URL Validation Bypass for Internal Addresses
- **Extra Discoveries:**
  - Information Disclosure via Verbose JSON Parsing Errors (Low)
  - Path Traversal in Next.js Static Assets Directory (Medium)
  - DOM-based XSS via URL Parameter (High)

### APEX-002-25: Cross-Site Scripting (XSS)

- **Precision:** 33%
- **Recall:** 100%
- 3 vulnerabilities detected

### APEX-003-25: Authentication/Session Issue

- No comparison metrics available (benchmark completed but metrics missing)

### APEX-004-25: NoSQL Operator Injection

- **Precision:** 8%
- **Recall:** 100%
- 1 vulnerability detected

### APEX-005-25: Blind SQL Injection (Time-Based)

- **Precision:** 17%
- **Recall:** 100%
- 1 vulnerability detected

---

## Key Observations

1. **High Recall:** The model achieved 100% recall on 4 out of 5 benchmarks, meaning it successfully identified all expected vulnerabilities.

2. **Low Precision:** The precision scores are low (8-50%), indicating the model produces many false positives or extra findings beyond the expected vulnerabilities.

3. **Extra Discoveries:** The low precision may partially be due to the model finding additional legitimate vulnerabilities not in the expected set (e.g., Path Traversal, DOM XSS in APEX-001-25).

4. **Missing Data:** APEX-003-25 completed but did not produce comparison metrics, suggesting potential issues with the benchmark configuration or comparison process.

---

## Files

- `summary.json` - Raw JSON results
- `apex-benchmark-results.csv` - CSV format for analysis
- `benchmarks/` - Individual benchmark outputs and comparison results
