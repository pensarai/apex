import { z } from "zod";

export const AttackPathSchema = z.array(
  z.object({
    applicationId: z.string().optional(),
    applicationName: z.string().optional(),
    host: z.string().optional(),
    relationshipType: z.string().optional(),
    notes: z.string().optional(),
  }),
);

export type AttackPath = z.infer<typeof AttackPathSchema>;
