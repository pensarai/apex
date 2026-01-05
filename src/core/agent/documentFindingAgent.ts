import { z } from 'zod';

// Backward-compatible Finding schema (toolCallDescription is optional for parsing old findings)
export const ApexFindingObject = z.object({
  title: z.string(),
  severity: z.preprocess((val) => {
    if (typeof val === "string") {
      const upper = val.toUpperCase();
      if (upper.includes("CRITICAL")) return "CRITICAL";
      if (upper.includes("HIGH")) return "HIGH";
      if (upper.includes("MEDIUM")) return "MEDIUM";
      if (upper.includes("LOW")) return "LOW";
    }
    return val;
  }, z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"])),
  description: z.string(),
  impact: z.string(),
  evidence: z.string(),
  endpoint: z.string(),
  pocPath: z.string(),
  remediation: z.string(),
  references: z.string().optional(),
  toolCallDescription: z.string().optional(), // Optional for backward compatibility
});

export type Finding = z.infer<typeof ApexFindingObject>;

// Re-export CreatePoc types
export type { CreatePocInput as CreatePocOpts, CreatePocResult } from './metaTestingAgent/types';
