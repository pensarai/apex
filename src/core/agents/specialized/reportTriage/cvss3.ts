import type { CVSSScorerResult } from "../cvssScorer";
import type { CvssSummary } from "./types";

type Cvss3Impact = "H" | "L" | "N";
type Cvss3Scope = "U" | "C";
type Cvss3UserInteraction = "N" | "R";

const AV_WEIGHT = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as const;
const AC_WEIGHT = { L: 0.77, H: 0.44 } as const;
const UI_WEIGHT = { N: 0.85, R: 0.62 } as const;
const IMPACT_WEIGHT = { H: 0.56, L: 0.22, N: 0 } as const;

const PR_WEIGHT: Record<Cvss3Scope, Record<"N" | "L" | "H", number>> = {
  U: { N: 0.85, L: 0.62, H: 0.27 },
  C: { N: 0.85, L: 0.68, H: 0.5 },
};

export function convertCvss4ToHackerOneCvss3(
  result: CVSSScorerResult,
): CvssSummary {
  const vector = toCvss3Vector(result.metrics);
  const score = calculateCvss3Score(vector);

  return {
    score,
    severity: severityForScore(score),
    vectorString: formatCvss3Vector(vector),
    reasoning: `${result.reasoning} Converted from CVSS 4.0 to HackerOne-compatible CVSS 3.0 for report submission.`,
  };
}

function toCvss3Vector(metrics: CVSSScorerResult["metrics"]) {
  const scope: Cvss3Scope =
    metrics.SC !== "N" || metrics.SI !== "N" || metrics.SA !== "N" ? "C" : "U";

  return {
    AV: metrics.AV,
    AC: metrics.AC === "H" || metrics.AT === "P" ? "H" : "L",
    PR: metrics.PR,
    UI: metrics.UI === "N" ? "N" : "R",
    S: scope,
    C: maxImpact(metrics.VC, metrics.SC),
    I: maxImpact(metrics.VI, metrics.SI),
    A: maxImpact(metrics.VA, metrics.SA),
  } as const;
}

function maxImpact(a: Cvss3Impact, b: Cvss3Impact): Cvss3Impact {
  if (a === "H" || b === "H") return "H";
  if (a === "L" || b === "L") return "L";
  return "N";
}

function formatCvss3Vector(vector: ReturnType<typeof toCvss3Vector>): string {
  return `CVSS:3.0/AV:${vector.AV}/AC:${vector.AC}/PR:${vector.PR}/UI:${vector.UI}/S:${vector.S}/C:${vector.C}/I:${vector.I}/A:${vector.A}`;
}

function calculateCvss3Score(vector: ReturnType<typeof toCvss3Vector>): number {
  const impact =
    1 -
    (1 - IMPACT_WEIGHT[vector.C]) *
      (1 - IMPACT_WEIGHT[vector.I]) *
      (1 - IMPACT_WEIGHT[vector.A]);
  if (impact <= 0) return 0;

  const impactSubScore =
    vector.S === "U"
      ? 6.42 * impact
      : 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15;

  const exploitability =
    8.22 *
    AV_WEIGHT[vector.AV] *
    AC_WEIGHT[vector.AC] *
    PR_WEIGHT[vector.S][vector.PR] *
    UI_WEIGHT[vector.UI];

  const baseScore =
    vector.S === "U"
      ? impactSubScore + exploitability
      : 1.08 * (impactSubScore + exploitability);

  return roundUp1Decimal(Math.min(baseScore, 10));
}

function roundUp1Decimal(value: number): number {
  return Math.ceil(value * 10) / 10;
}

function severityForScore(score: number): CvssSummary["severity"] {
  if (score === 0) return "NONE";
  if (score < 4) return "LOW";
  if (score < 7) return "MEDIUM";
  if (score < 9) return "HIGH";
  return "CRITICAL";
}
