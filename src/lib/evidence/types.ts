import { z } from "zod";

export const EvidenceFileEntrySchema = z.object({
  path: z.string(),
  type: z.enum(["http-response", "screenshot", "poc-output", "raw-evidence"]),
  description: z.string(),
});

export type EvidenceFileEntry = z.infer<typeof EvidenceFileEntrySchema>;
