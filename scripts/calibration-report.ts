#!/usr/bin/env bun
/**
 * Calibration report for Apex benchmark runs.
 *
 * Reads the committed Argus benchmark traces and reports the agent's
 * over-claim gap: how often it submits findings that are not the real
 * vulnerability, relative to what it actually captures. This complements the
 * existing precision/recall reporting by turning the over-claim gap into a
 * single tracked number, so judge/prompt changes can be measured for
 * calibration regression (see issue #732).
 *
 * Pure offline analysis of committed artifacts. No benchmark runs, no API calls.
 *
 *   over-claim rate (per run) = 1 - precision = FP / (TP + FP)
 *     TP = comparison.matched.length   (expected vuln confirmed)
 *     FP = comparison.extra.length     (surplus claims that matched nothing expected)
 *     FN = comparison.missed.length    (expected vuln not found)
 *
 * Usage: bun run scripts/calibration-report.ts [runsDir]
 *   runsDir defaults to benchmarks/argus/runs
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, dirname, basename } from "node:path";

interface Comparison {
  matched?: unknown[];
  missed?: { severity?: string }[];
  extra?: { severity?: string; assessment?: string }[];
}

interface RunCalibration {
  id: string;
  tp: number;
  fn: number;
  fp: number;
  precision: number;
  recall: number;
  overClaimRate: number;
  flagCaptured: boolean;
  extraHigh: number;
  extraCritical: number;
  selfFlaggedFp: number;
  pureOverClaim: boolean;
}

function walk(dir: string, name: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    let s;
    try {
      s = statSync(p);
    } catch {
      continue;
    }
    if (s.isDirectory()) walk(p, name, out);
    else if (entry === name) out.push(p);
  }
  return out;
}

function countSeverity(items: { severity?: string }[] | undefined, level: string): number {
  return (items ?? []).filter((i) => (i.severity ?? "").toLowerCase() === level).length;
}

function flagCapturedFor(comparisonPath: string): boolean {
  const sibling = join(dirname(comparisonPath), "benchmark_results.json");
  try {
    const d = JSON.parse(readFileSync(sibling, "utf8"));
    return Boolean(d?.flagDetection?.detected);
  } catch {
    return false;
  }
}

function analyze(runsDir: string): RunCalibration[] {
  const rows: RunCalibration[] = [];
  for (const f of walk(runsDir, "comparison-results.json")) {
    let c: Comparison;
    try {
      c = JSON.parse(readFileSync(f, "utf8"));
    } catch {
      continue;
    }
    const tp = (c.matched ?? []).length;
    const fn = (c.missed ?? []).length;
    const fp = (c.extra ?? []).length;
    if (tp + fn + fp === 0) continue;
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const selfFlaggedFp = (c.extra ?? []).filter((e) =>
      /false.?positive|unconfirmed/i.test(e.assessment ?? "")
    ).length;
    rows.push({
      id: basename(dirname(f)),
      tp,
      fn,
      fp,
      precision,
      recall,
      overClaimRate: 1 - precision,
      flagCaptured: flagCapturedFor(f),
      extraHigh: countSeverity(c.extra, "high"),
      extraCritical: countSeverity(c.extra, "critical"),
      selfFlaggedFp,
      pureOverClaim: tp === 0 && fp > 0,
    });
  }
  return rows;
}

function mean(xs: number[]): number {
  return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0;
}

function main(): void {
  const runsDir = process.argv[2] ?? "benchmarks/argus/runs";
  const rows = analyze(runsDir);
  if (rows.length === 0) {
    console.error(`No comparison-results.json found under ${runsDir}`);
    process.exit(1);
  }

  const tp = rows.reduce((a, r) => a + r.tp, 0);
  const fn = rows.reduce((a, r) => a + r.fn, 0);
  const fp = rows.reduce((a, r) => a + r.fp, 0);
  const overClaiming = rows.filter((r) => r.precision < r.recall).length;
  const pure = rows.filter((r) => r.pureOverClaim).length;
  const flags = rows.filter((r) => r.flagCaptured).length;
  const extraHigh = rows.reduce((a, r) => a + r.extraHigh, 0);
  const extraCritical = rows.reduce((a, r) => a + r.extraCritical, 0);
  const selfFp = rows.reduce((a, r) => a + r.selfFlaggedFp, 0);

  console.log("\nCALIBRATION REPORT  ·  over-claim gap on committed Argus runs\n");
  console.log(
    "benchmark".padEnd(16) +
      "prec".padStart(7) +
      "recall".padStart(8) +
      "overclaim".padStart(11) +
      "flag".padStart(6) +
      "extraH/C".padStart(10) +
      "selfFP".padStart(8)
  );
  console.log("-".repeat(74));
  for (const r of [...rows].sort((a, b) => b.overClaimRate - a.overClaimRate)) {
    console.log(
      r.id.padEnd(16) +
        r.precision.toFixed(3).padStart(7) +
        r.recall.toFixed(3).padStart(8) +
        r.overClaimRate.toFixed(3).padStart(11) +
        (r.flagCaptured ? "Y" : "N").padStart(6) +
        `${r.extraHigh}/${r.extraCritical}`.padStart(10) +
        String(r.selfFlaggedFp).padStart(8)
    );
  }
  console.log("-".repeat(74));
  console.log(
    [
      ``,
      `runs analysed         ${rows.length}`,
      `mean precision        ${mean(rows.map((r) => r.precision)).toFixed(3)}`,
      `mean recall           ${mean(rows.map((r) => r.recall)).toFixed(3)}`,
      `mean over-claim rate  ${mean(rows.map((r) => r.overClaimRate)).toFixed(3)}   (1 - precision)`,
      `pooled precision      ${(tp / (tp + fp)).toFixed(3)}   (${tp} matched / ${tp + fp})`,
      `pooled recall         ${(tp / (tp + fn)).toFixed(3)}   (${tp} matched / ${tp + fn})`,
      `over-claiming runs    ${overClaiming}/${rows.length}   (precision < recall)`,
      `pure over-claim runs  ${pure}/${rows.length}   (0 verified, >0 submitted)`,
      `flag captured         ${flags}/${rows.length}`,
      `extra findings        ${fp}   (${extraHigh} high, ${extraCritical} critical)`,
      `agent-flagged FP      ${selfFp}   (comparison step labelled false-positive / unconfirmed)`,
      ``,
    ].join("\n")
  );
}

main();
