import { z } from "zod";

/**
 * Schema for a single CWE classification entry.
 *
 * Each entry pairs a CWE identifier (e.g., "CWE-89") with a reasoning
 * string explaining why that CWE applies to the observed vulnerability.
 */
export const CweEntrySchema = z.object({
  id: z.string().regex(/^CWE-\d+$/, "Must be CWE-<number> format"),
  reasoning: z
    .string()
    .describe("Why this CWE applies to the observed vulnerability"),
});

export type CweEntry = z.infer<typeof CweEntrySchema>;

/**
 * A CWE entry that has been validated against the CWE database
 * and enriched with the canonical MITRE name.
 */
export const ValidatedCweEntrySchema = CweEntrySchema.extend({
  name: z.string().describe("Canonical CWE name from the MITRE database"),
});

export type ValidatedCweEntry = z.infer<typeof ValidatedCweEntrySchema>;

/**
 * Type guard: does this CWE entry have a canonical name?
 * Use in renderers to safely access the `name` field on entries
 * that may be either CweEntry or ValidatedCweEntry.
 */
export function hasCanonicalName(
  cwe: CweEntry | ValidatedCweEntry,
): cwe is ValidatedCweEntry {
  return "name" in cwe && typeof (cwe as ValidatedCweEntry).name === "string";
}
