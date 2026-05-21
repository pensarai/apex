import { z } from "zod";

export const FINDING_SEVERITIES = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL",
] as const;

export const FindingSeveritySchema = z.enum(FINDING_SEVERITIES);

export function normalizeFindingSeverity(value: unknown): unknown {
  if (typeof value !== "string") return value;

  const upper = value.toUpperCase();
  if (upper.includes("CRITICAL")) return "CRITICAL";
  if (upper.includes("HIGH")) return "HIGH";
  if (upper.includes("MEDIUM")) return "MEDIUM";
  if (upper.includes("LOW")) return "LOW";
  if (upper.includes("INFORMATIONAL") || upper === "INFO" || upper === "NONE") {
    return "INFORMATIONAL";
  }

  return value;
}
