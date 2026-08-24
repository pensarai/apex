import type { FindingsRegistry } from "../../../findings/registry";
import type { Finding } from "../../offSecAgent";
import type { BountyReport, DupCheckResult } from "./types";

function reportClaimedSeverityToFindingSeverity(
  claimed: BountyReport["claimedSeverity"],
): Finding["severity"] {
  switch (claimed) {
    case "CRITICAL":
      return "CRITICAL";
    case "HIGH":
      return "HIGH";
    case "MEDIUM":
      return "MEDIUM";
    // LOW, INFORMATIONAL, and UNKNOWN all collapse to LOW — severity is
    // not used by the dedup tiers (only title, endpoint, description,
    // evidence) so this is safe.
    default:
      return "LOW";
  }
}

/**
 * Adapt a parsed {@link BountyReport} into the minimal {@link Finding} shape
 * required by the dedup helpers in `findings/registry.ts`.
 *
 * We only fill the fields that the dedup tiers actually consult:
 *   - title, endpoint        → exact-key + app-wide-key fingerprint
 *   - description, evidence  → content-aware classification (`classifyFromContent`)
 *   - severity               → unused by string-based dedup but required by the schema
 */
export function reportToFindingShape(report: BountyReport): Finding {
  return {
    title: report.title,
    severity: reportClaimedSeverityToFindingSeverity(report.claimedSeverity),
    description: report.description,
    impact: report.impact,
    evidence: [report.pocCurl, ...report.pocSteps].filter(Boolean).join("\n"),
    endpoint: report.affectedUrl,
    pocPath: "",
    remediation: "",
  };
}

/**
 * Check whether the inbound report duplicates anything already in the
 * findings registry. Uses the registry's synchronous Tier 1 + Tier 2 dedup
 * (exact endpoint+class match, application-wide title-stem match).
 *
 * Tier 3 (LLM semantic dedup) is intentionally skipped here — triage runs
 * against a potentially empty or remote registry and the marginal cost of
 * a paraphrased duplicate slipping through is low. The user can always
 * mark it duplicate during review.
 */
export function checkDuplicate(opts: {
  report: BountyReport;
  registry: FindingsRegistry;
}): DupCheckResult {
  const findingShape = reportToFindingShape(opts.report);
  const result = opts.registry.isDuplicate(findingShape);

  if (!result.duplicate) {
    return { duplicate: false, matchType: "none" };
  }

  return {
    duplicate: true,
    matchType: result.matchType ?? "exact",
    matchedTitle: result.matchedFinding?.title,
    matchedEndpoint: result.matchedFinding?.endpoint,
  };
}
