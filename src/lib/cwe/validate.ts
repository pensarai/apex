import { CWE_CATALOG } from "./cwe-catalog";
import type { CweEntry, ValidatedCweEntry } from "./types";

export interface CweValidationResult {
  /** Validated and enriched CWE entries (only those found in the database) */
  validated: ValidatedCweEntry[];
  /** CWE entries that were removed because the ID is unknown */
  dropped: Array<{ id: string; reason: string }>;
}

/**
 * Parse the numeric portion from a CWE ID string like "CWE-89".
 * Returns null if the format is unexpected.
 */
function parseNumericCweId(id: string): number | null {
  const match = id.match(/^CWE-(\d+)$/);
  if (!match) return null;
  return parseInt(match[1], 10);
}

/**
 * Validate LLM-returned CWE entries against the canonical MITRE database.
 * Unknown/hallucinated IDs are dropped; valid ones are enriched with canonical names.
 */
export function validateCweEntries(entries: CweEntry[]): CweValidationResult {
  const validated: ValidatedCweEntry[] = [];
  const dropped: Array<{ id: string; reason: string }> = [];

  for (const entry of entries) {
    const numericId = parseNumericCweId(entry.id);
    if (numericId === null) {
      dropped.push({ id: entry.id, reason: "Could not parse numeric ID" });
      continue;
    }

    const canonicalName = CWE_CATALOG.get(numericId);
    if (canonicalName === undefined) {
      dropped.push({
        id: entry.id,
        reason: `CWE ID not found in database`,
      });
      continue;
    }

    validated.push({
      id: entry.id,
      name: canonicalName,
      reasoning: entry.reasoning,
    });
  }

  return { validated, dropped };
}
