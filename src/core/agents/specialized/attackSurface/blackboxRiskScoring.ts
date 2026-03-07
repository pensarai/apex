import type { RiskScore } from "../whiteboxAttackSurface/types";
import type { RiskLevel, AssetType, AssetDetails } from "./schemas";

/**
 * Base score mapping from risk level to total score.
 */
const RISK_LEVEL_BASE_SCORE: Record<RiskLevel, number> = {
  CRITICAL: 10,
  HIGH: 8,
  MEDIUM: 5,
  LOW: 2,
};

/**
 * Heuristic exposure scores by risk level.
 *
 * Blackbox assets are discovered from the outside, so exposure is
 * generally higher than for whitebox endpoints. The agent's riskLevel
 * already encodes how exposed/sensitive the asset is.
 */
const EXPOSURE_BY_RISK: Record<RiskLevel, number> = {
  CRITICAL: 3,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

/**
 * Compute a heuristic {@link RiskScore} for a blackbox-discovered asset.
 *
 * Since there is no source code to read, we derive the four breakdown
 * dimensions from the agent-assigned `riskLevel`, the `assetType`, and
 * observable metadata (authentication, services, technology stack).
 *
 * The breakdown dimensions match the whitebox model:
 *   - **exposure** (0-3): How reachable is the asset from the outside?
 *   - **dataSensitivity** (0-3): How sensitive is the data it likely handles?
 *   - **functionCriticality** (0-2): How critical is the business function?
 *   - **securityIndicators** (0-2): Are there observable security concerns?
 */
export function computeBlackboxRiskScore(
  riskLevel: RiskLevel,
  assetType: AssetType,
  details?: AssetDetails,
  notes?: string,
): RiskScore {
  const exposure = computeExposure(riskLevel, details);
  const dataSensitivity = computeDataSensitivity(riskLevel, assetType, details);
  const functionCriticality = computeFunctionCriticality(
    riskLevel,
    assetType,
    details,
    notes,
  );
  const securityIndicators = computeSecurityIndicators(
    riskLevel,
    details,
    notes,
  );

  const rawSum =
    exposure + dataSensitivity + functionCriticality + securityIndicators;
  const score = Math.min(10, Math.max(0, rawSum));

  const baseScore = RISK_LEVEL_BASE_SCORE[riskLevel] ?? 0;
  const explanation = buildExplanation(riskLevel, assetType, baseScore, score, {
    exposure,
    dataSensitivity,
    functionCriticality,
    securityIndicators,
  });

  return {
    score,
    explanation,
    breakdown: {
      exposure,
      dataSensitivity,
      functionCriticality,
      securityIndicators,
    },
  };
}

// ---------------------------------------------------------------------------
// Dimension helpers
// ---------------------------------------------------------------------------

function computeExposure(riskLevel: RiskLevel, details?: AssetDetails): number {
  let base = EXPOSURE_BY_RISK[riskLevel] ?? 1;

  if (details?.authentication) {
    const authLower = details.authentication.toLowerCase();
    if (
      authLower.includes("none") ||
      authLower.includes("no auth") ||
      authLower.includes("public")
    ) {
      base = Math.max(base, 3);
    } else if (
      authLower.includes("admin") ||
      authLower.includes("privileged")
    ) {
      base = Math.min(base, 1);
    }
  }

  return Math.min(3, Math.max(0, base));
}

function computeDataSensitivity(
  riskLevel: RiskLevel,
  assetType: AssetType,
  details?: AssetDetails,
): number {
  if (riskLevel === "CRITICAL") return 3;

  let score = riskLevel === "HIGH" ? 2 : riskLevel === "MEDIUM" ? 1 : 0;

  if (assetType === "admin_panel") score = Math.max(score, 2);

  const techStr = (details?.technology ?? []).join(" ").toLowerCase();
  if (
    techStr.includes("database") ||
    techStr.includes("postgres") ||
    techStr.includes("mysql") ||
    techStr.includes("mongo") ||
    techStr.includes("redis")
  ) {
    score = Math.max(score, 2);
  }

  return Math.min(3, score);
}

function computeFunctionCriticality(
  riskLevel: RiskLevel,
  assetType: AssetType,
  details?: AssetDetails,
  notes?: string,
): number {
  if (assetType === "admin_panel") return 2;
  if (riskLevel === "CRITICAL") return 2;

  const searchText = [
    ...(details?.services ?? []),
    ...(details?.technology ?? []),
    details?.authentication ?? "",
    notes ?? "",
  ]
    .join(" ")
    .toLowerCase();

  const criticalPatterns = [
    "auth",
    "login",
    "payment",
    "checkout",
    "password",
    "oauth",
    "sso",
    "saml",
    "admin",
    "transfer",
    "billing",
  ];
  if (criticalPatterns.some((p) => searchText.includes(p))) return 2;

  if (riskLevel === "HIGH") return 1;
  if (assetType === "api" || assetType === "web_application") return 1;

  return 0;
}

function computeSecurityIndicators(
  riskLevel: RiskLevel,
  details?: AssetDetails,
  notes?: string,
): number {
  if (riskLevel === "CRITICAL") return 2;

  const searchText = [
    ...(details?.services ?? []),
    ...(details?.technology ?? []),
    notes ?? "",
    String(details?.status ?? ""),
  ]
    .join(" ")
    .toLowerCase();

  const criticalIndicators = [
    "injection",
    "sqli",
    "xss",
    "rce",
    "traversal",
    "deserialization",
    "hardcoded",
    "default credentials",
    "vulnerable",
    "cve-",
    "exploit",
  ];
  if (criticalIndicators.some((p) => searchText.includes(p))) return 2;

  const moderateIndicators = [
    "outdated",
    "deprecated",
    "insecure",
    "http:",
    "self-signed",
    "debug",
    "verbose error",
    "stack trace",
    "cors",
    "misconfigur",
  ];
  if (moderateIndicators.some((p) => searchText.includes(p))) return 1;

  if (riskLevel === "HIGH") return 1;

  return 0;
}

// ---------------------------------------------------------------------------
// Explanation builder
// ---------------------------------------------------------------------------

function buildExplanation(
  riskLevel: RiskLevel,
  assetType: AssetType,
  _baseScore: number,
  totalScore: number,
  breakdown: {
    exposure: number;
    dataSensitivity: number;
    functionCriticality: number;
    securityIndicators: number;
  },
): string {
  const parts: string[] = [
    `${riskLevel} risk ${assetType.replace(/_/g, " ")} (score ${totalScore}/10).`,
  ];

  if (breakdown.exposure >= 3) parts.push("Publicly exposed.");
  else if (breakdown.exposure >= 2) parts.push("Externally accessible.");

  if (breakdown.dataSensitivity >= 3)
    parts.push("Likely handles sensitive data.");
  else if (breakdown.dataSensitivity >= 2)
    parts.push("May handle business-critical data.");

  if (breakdown.functionCriticality >= 2) parts.push("Critical function.");
  else if (breakdown.functionCriticality >= 1) parts.push("Core function.");

  if (breakdown.securityIndicators >= 2)
    parts.push("Security concerns observed.");
  else if (breakdown.securityIndicators >= 1)
    parts.push("Moderate security concerns.");

  return parts.join(" ");
}
