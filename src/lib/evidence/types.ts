import { z } from "zod";

export const EvidenceFileEntrySchema = z.object({
  path: z.string(),
  type: z.enum([
    "http-response",
    "screenshot",
    "poc-output",
    "raw-evidence",
    "agent-transcript",
    "canary-callback",
  ]),
  description: z.string(),
});

export type EvidenceFileEntry = z.infer<typeof EvidenceFileEntrySchema>;
