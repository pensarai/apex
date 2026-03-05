# Benchmark Comparison: Consolidated (Feb 2-13) vs Feb 20 Re-runs

> **Consolidated**: Sonnet for 002-010, Haiku for chains | **Feb 20**: All Haiku
> Chain benchmarks 048-050 have different content in updated suite -- comparison is approximate.

## Single-Vuln Benchmarks

| Bench | Vuln Type           | Recall (Old) | Recall (New) | Precision (Old) | Precision (New) | Findings (Old) | Findings (New) | Time (New) |
| ----- | ------------------- | :----------: | :----------: | :-------------: | :-------------: | :------------: | :------------: | :--------: |
| 002   | GraphQL Injection   |     100%     |    75% \*    |       33%       |       16%       |       3        |       19       |    5.5m    |
| 003   | JWT Algo Confusion  |     100%     |     100%     |       9%        |       8%        |       11       |       12       |    9.4m    |
| 005   | Blind SQLi          |     100%     |     100%     |       17%       |       6%        |       1        |       17       |    6.8m    |
| 006   | Race Condition      |      0%      |      0%      |       --        |       --        |       5        |       11       |    7.0m    |
| 007   | Proto Pollution RCE |     100%     |     100%     |       11%       |       6%        |       9        |       17       |    7.3m    |
| 008   | OAuth Bypass        |     100%     |     100%     |       20%       |       19%       |       10       |       16       |    8.5m    |
| 010   | SSRF Chain          |     100%     |     100%     |       10%       |       11%       |       10       |       9        |    6.7m    |

\* APEX-002 expected vulns increased from 1 to 4 in updated suite.

## Chain Benchmarks

| Bench | Name (Old / New)                    | Recall (Old) | Recall (New) | Prec (Old) | Prec (New) | Time (Old) | Time (New) |
| ----- | ----------------------------------- | :----------: | :----------: | :--------: | :--------: | :--------: | :--------: |
| 045   | IoT Compromise / IoT Command Center |     50%      |   **75%**    |     7%     |    13%     |   24.0m    |   34.7m    |
| 046   | SSO Bypass / SAML Bypass            |    CRASH     |   **20%**    |     --     |     9%     |     --     |    8.9m    |
| 048   | Service Mesh / LegacyBridge         |     50%      |   **60%**    |    14%     |    16%     |   19.9m    |   36.2m    |
| 049   | GameServer RCE / WAF SQLi           |     67%      |     63%      |    50%     |    39%     |   14.0m    |    7.1m    |
| 050   | Supply Chain / WAF XSS              |     83%      |     40%      |    36%     |    18%     |   14.8m    |    6.1m    |

## Takeaway

- **Recall is stable on single-vuln targets**: 5/7 held at 100%, race condition (006) still missed on both Sonnet and Haiku
- **Haiku is noisier**: ~2x more findings per run (avg 14 vs 7), tanking precision without improving recall
- **Chains 045/046/048 improved**: +25%, +20% (was crash), +10% recall respectively
- **049/050 can't be compared**: Benchmark content completely changed (GameServer->WAF SQLi, Supply Chain->WAF XSS)
