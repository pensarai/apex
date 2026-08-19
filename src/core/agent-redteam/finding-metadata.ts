import { z } from "zod";

export const AgentRedTeamFindingMetadataSchema = z.object({
  campaignId: z.string(),
  attemptId: z.string(),
  evaluationId: z.string(),
  techniqueId: z.string(),
  vector: z.string(),
  surface: z.string(),
  oracleIds: z.array(z.string()),
  evidenceStrength: z.enum([
    "deterministic",
    "target-artifact",
    "model-asserted",
  ]),
  confidence: z.number().min(0).max(1),
});

export type AgentRedTeamFindingMetadata = z.infer<
  typeof AgentRedTeamFindingMetadataSchema
>;
