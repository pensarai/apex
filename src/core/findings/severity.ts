import { z } from "zod";
import type { CVSS4Severity } from "../../lib/cvss";

export const FINDING_SEVERITIES = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL",
] as const;

export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];

export const FindingSeveritySchema = z.preprocess((val) => {
  if (typeof val === "string") {
    const upper = val.toUpperCase();
    if (upper.includes("CRITICAL")) return "CRITICAL";
    if (upper.includes("HIGH")) return "HIGH";
    if (upper.includes("MEDIUM")) return "MEDIUM";
    if (upper.includes("LOW")) return "LOW";
    if (upper.includes("INFORMATIONAL") || upper.includes("INFO")) {
      return "INFORMATIONAL";
    }
  }
  return val;
}, z.enum(FINDING_SEVERITIES));

export const FINDING_SEVERITY_ORDER = FINDING_SEVERITIES;

export function findingSeverityFromCvssSeverity(
  severity: CVSS4Severity,
): FindingSeverity {
  return severity === "NONE" ? "INFORMATIONAL" : severity;
}
