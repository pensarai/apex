/**
 * Threat Model Benchmark — Regression Comparison
 *
 * Compares current run against a previous run's summary.json.
 */

import type { SuiteResult, RegressionResult } from "../types";

const SIGNIFICANT_THRESHOLD = 5; // % change to flag

export function compareRuns(
  current: SuiteResult,
  previous: SuiteResult,
): RegressionResult {
  const overallDelta =
    current.headline.overallScore - previous.headline.overallScore;

  const significantChanges: RegressionResult["significantChanges"] = [];

  // Compare per-app scores
  for (const appId of Object.keys(current.perApp)) {
    const curr = current.perApp[appId];
    const prev = previous.perApp[appId];
    if (!prev) continue;

    // Overall
    const delta = curr.overall - prev.overall;
    if (Math.abs(delta) > SIGNIFICANT_THRESHOLD) {
      significantChanges.push({
        metric: "overall",
        app: appId,
        delta,
        direction: delta > 0 ? "improvement" : "regression",
      });
    }

    // Vulnerability recall
    const currVr = curr.discovery?.vulnerabilityRecall;
    const prevVr = prev.discovery?.vulnerabilityRecall;
    if (currVr !== undefined && prevVr !== undefined) {
      const vrDelta = (currVr - prevVr) * 100;
      if (Math.abs(vrDelta) > SIGNIFICANT_THRESHOLD) {
        significantChanges.push({
          metric: "vulnerabilityRecall",
          app: appId,
          delta: vrDelta,
          direction: vrDelta > 0 ? "improvement" : "regression",
        });
      }
    }

    // False positive rate (lower is better, so inverted)
    const currFp = curr.discovery?.falsePositiveRate;
    const prevFp = prev.discovery?.falsePositiveRate;
    if (currFp !== undefined && prevFp !== undefined) {
      const fpDelta = (currFp - prevFp) * 100;
      if (Math.abs(fpDelta) > SIGNIFICANT_THRESHOLD) {
        significantChanges.push({
          metric: "falsePositiveRate",
          app: appId,
          delta: fpDelta,
          direction: fpDelta < 0 ? "improvement" : "regression",
        });
      }
    }

    // Grounding
    const currG = curr.grounding?.score;
    const prevG = prev.grounding?.score;
    if (currG !== undefined && prevG !== undefined) {
      const gDelta = (currG - prevG) * 100;
      if (Math.abs(gDelta) > SIGNIFICANT_THRESHOLD) {
        significantChanges.push({
          metric: "grounding",
          app: appId,
          delta: gDelta,
          direction: gDelta > 0 ? "improvement" : "regression",
        });
      }
    }
  }

  return {
    previousRunId: previous.runId,
    overallDelta,
    significantChanges,
  };
}
