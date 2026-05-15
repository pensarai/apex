import { z } from "zod";
import { SessionIdSchema } from "./ids";

export const SessionScopeSchema = z.enum([
  "scan",
  "recon_job",
  "sandbox_test",
  "credential_test",
  "apex_session",
  "chat",
]);
export type SessionScope = z.infer<typeof SessionScopeSchema>;

export const SessionStatusSchema = z.enum([
  "pending",
  "running",
  "completed",
  "error",
  "paused",
]);
export type SessionStatus = z.infer<typeof SessionStatusSchema>;

export const ExecutionSessionSchema = z.object({
  id: SessionIdSchema,
  workspaceId: z.string().nullable(),
  projectId: z.string().nullable(),
  scope: SessionScopeSchema,
  title: z.string().nullable(),
  agent: z.string().nullable(),
  model: z.string().nullable(),
  status: SessionStatusSchema,
  timeCreated: z.string().datetime(),
  timeUpdated: z.string().datetime(),
  timeCompleted: z.string().datetime().nullable(),
  cost: z.number().nonnegative().nullable(),
  tokensInput: z.number().int().nonnegative().nullable(),
  tokensOutput: z.number().int().nonnegative().nullable(),
  tokensReasoning: z.number().int().nonnegative().nullable(),
  tokensCacheRead: z.number().int().nonnegative().nullable(),
  tokensCacheWrite: z.number().int().nonnegative().nullable(),
  revert: z.unknown().nullable(),
});

export type ExecutionSession = z.infer<typeof ExecutionSessionSchema>;
