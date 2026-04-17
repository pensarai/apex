import { z } from "zod";

export const TestCaseResponseSchema = z.object({
  narrative: z
    .string()
    .min(30)
    .max(3000)
    .describe(
      "Terminal-style first-person account of what you did: what you probed, what you observed, what you concluded. Short declarative lines.",
    ),
  summary: z
    .string()
    .max(400)
    .describe(
      "One-sentence technical summary of findings — e.g. 'Target WAF blocked 8/10 OWASP categories; SSRF and XXE went through.'",
    ),
  detectionsEmitted: z
    .number()
    .int()
    .nonnegative()
    .describe(
      "Your running count of detection events you observed during the run. Used for reconciliation with the persisted event list.",
    ),
});

export type TestCaseResponse = z.infer<typeof TestCaseResponseSchema>;
