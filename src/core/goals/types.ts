import { randomUUID } from "node:crypto";
import { z } from "zod";

export const GOAL_LIMITS = {
  defaultMaxRounds: 50,
  maxRoundsCeiling: 200,
  maxStalledRounds: 3,
  objectiveMaxChars: 4_000,
} as const;

export const goalMaxRoundsSchema = z
  .number()
  .int()
  .min(1)
  .max(GOAL_LIMITS.maxRoundsCeiling);

export const newGoalSchema = z.object({
  objective: z.string().trim().min(1).max(GOAL_LIMITS.objectiveMaxChars),
  maxRounds: goalMaxRoundsSchema.optional(),
});

export const GOAL_STATUSES = [
  "active",
  "complete",
  "blocked",
  "cancelled",
] as const;
export type GoalStatus = (typeof GOAL_STATUSES)[number];

export const GOAL_REASONS = [
  "replaced",
  "ended_by_operator",
  "agent_blocked",
  "no_progress",
  "rounds",
  "turn_failed",
  "turn_refused",
] as const;
export type GoalReason = (typeof GOAL_REASONS)[number];

/** `source:session/mSEQ/pINDEX`: message sequence and part index within a session. */
export const evidenceAddressSchema = z
  .string()
  .regex(/^(console|local):[^/\s]+\/m\d+\/p\d+$/);
export type EvidenceAddress = z.infer<typeof evidenceAddressSchema>;

export const goalSchema = z.object({
  id: z.string().min(1),
  sessionId: z.string().min(1),
  objective: z.string().min(1).max(GOAL_LIMITS.objectiveMaxChars),
  status: z.enum(GOAL_STATUSES),
  reason: z.enum(GOAL_REASONS).nullable(),
  detail: z.string().nullable(),
  rounds: z.number().int().min(0),
  stalledRounds: z.number().int().min(0),
  maxRounds: goalMaxRoundsSchema,
  maxStalledRounds: z.number().int().min(1),
  completion: z
    .object({
      summary: z.string(),
      evidence: z.array(evidenceAddressSchema),
      claimedAt: z.string(),
    })
    .nullable(),
  startedAt: z.string(),
  settledAt: z.string().nullable(),
});
export type Goal = z.infer<typeof goalSchema>;

export function createGoal(
  input: { sessionId: string; objective: string; maxRounds?: number },
  now: Date = new Date(),
): Goal {
  const { objective, maxRounds } = newGoalSchema.parse(input);
  return {
    id: randomUUID(),
    sessionId: input.sessionId,
    objective,
    status: "active",
    reason: null,
    detail: null,
    rounds: 0,
    stalledRounds: 0,
    maxRounds: maxRounds ?? GOAL_LIMITS.defaultMaxRounds,
    maxStalledRounds: GOAL_LIMITS.maxStalledRounds,
    completion: null,
    startedAt: now.toISOString(),
    settledAt: null,
  };
}

export function endGoal(
  goal: Goal,
  status: Exclude<GoalStatus, "active">,
  reason: GoalReason | null,
  detail: string | null,
  now: Date = new Date(),
): Goal {
  return { ...goal, status, reason, detail, settledAt: now.toISOString() };
}
