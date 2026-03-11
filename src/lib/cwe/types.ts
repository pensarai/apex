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
