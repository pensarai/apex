import { createHash } from "node:crypto";
import { z } from "zod";
import type { EngagementPair, EngagementPlan } from "./engagementPlan";

const Id = z.string().min(1).max(120);
const Evidence = z.string().trim().min(1);

export const CoverageObligationSchema = z.object({
  id: Id,
  kind: z.enum(["boundary", "control", "threat"]),
  description: Evidence,
  targetIds: z.array(Id).min(1),
  verification: Evidence,
});
export type CoverageObligation = z.infer<typeof CoverageObligationSchema>;

export const CoverageResultSchema = z.object({
  targetId: Id,
  objectiveId: Id,
  status: z.enum(["tested", "blocked"]),
  summary: Evidence,
  evidence: Evidence,
});
export type CoverageResult = z.infer<typeof CoverageResultSchema>;

export const MissionResultSchema = z.object({
  summary: Evidence,
  coverage: z.array(CoverageResultSchema),
  reportedFindings: z.array(z.string()).default([]),
});
export type MissionResult = z.infer<typeof MissionResultSchema>;

export type EngagementMission = EngagementPlan["missions"][number] & {
  parentId?: string;
  obligationIds: string[];
  chainIds: string[];
  status:
    | "pending"
    | "running"
    | "submitted"
    | "completed"
    | "failed"
    | "cancelled";
  workerId: string;
  attempt: number;
  followUp?: string;
  error?: string;
  progress?: string;
  result?: MissionResult;
};

export const ChainHypothesisSchema = z.object({
  id: Id,
  targetIds: z.array(Id).min(1),
  hypothesis: Evidence,
  prerequisites: z.array(Evidence).min(1),
  steps: z.array(Evidence).min(1),
  impact: Evidence,
});
export type ChainHypothesis = z.infer<typeof ChainHypothesisSchema> & {
  status: "open" | "validated" | "disproved" | "blocked";
  evidence?: string;
  landedIds?: string[];
};

export type LandedResult = {
  id: string;
  missionId: string;
  attempt: number;
  obligationIds: string[];
  chainIds: string[];
  acceptedBy: "engagement-lead";
  acceptedAt: string;
  review: string;
  result: MissionResult;
};

export type ObligationResult = {
  obligationId: string;
  status: "tested" | "blocked";
  evidence: string;
  landedIds: string[];
};

export interface EngagementState {
  version: 2;
  planHash: string;
  revision: number;
  missions: EngagementMission[];
  coverage: CoverageResult[];
  reportedFindings: string[];
  landed: LandedResult[];
  obligations: CoverageObligation[];
  obligationResults: ObligationResult[];
  chains: ChainHypothesis[];
  additionalObjectives: Array<EngagementPair & { text: string }>;
}

export const EngagementAssessmentSchema = z.object({
  status: z.enum(["complete", "incomplete", "deadline"]),
  deadlineAt: z.string().optional(),
  summary: z.string(),
  coverage: z.array(
    z.object({
      targetId: z.string(),
      objectiveId: z.string(),
      status: z.enum(["tested", "blocked", "unresolved"]),
      summary: z.string(),
      evidence: z.string(),
    }),
  ),
  exclusions: z.array(z.object({ targetId: z.string(), reason: z.string() })),
  obligations: z.array(
    CoverageObligationSchema.extend({
      status: z.enum(["tested", "blocked", "unresolved"]),
      evidence: z.string(),
      landedIds: z.array(z.string()),
    }),
  ),
  chains: z.array(
    ChainHypothesisSchema.extend({
      status: z.enum(["open", "validated", "disproved", "blocked"]),
      evidence: z.string().optional(),
      landedIds: z.array(z.string()).optional(),
    }),
  ),
  landed: z.array(
    z.object({
      id: z.string(),
      missionId: z.string(),
      attempt: z.number(),
      obligationIds: z.array(z.string()),
      chainIds: z.array(z.string()),
      acceptedBy: z.literal("engagement-lead"),
      acceptedAt: z.string(),
      review: z.string(),
      result: MissionResultSchema,
    }),
  ),
  unfinishedMissions: z.array(
    z.object({
      id: z.string(),
      status: z.string(),
      error: z.string().optional(),
      result: MissionResultSchema.optional(),
    }),
  ),
});
export type EngagementAssessment = z.infer<typeof EngagementAssessmentSchema>;

export function validateCoverageObligations(
  obligations: CoverageObligation[],
  targetIds: Set<string>,
): CoverageObligation[] {
  const parsed = z.array(CoverageObligationSchema).parse(obligations);
  const ids = new Set<string>();
  for (const obligation of parsed) {
    if (ids.has(obligation.id))
      throw new Error(`Duplicate obligation: ${obligation.id}`);
    ids.add(obligation.id);
    if (obligation.targetIds.some((id) => !targetIds.has(id)))
      throw new Error(
        `Obligation ${obligation.id} contains an out-of-scope target`,
      );
  }
  return parsed;
}

export function reopenMissionCoverage(
  state: EngagementState,
  mission: Pick<EngagementMission, "obligationIds" | "chainIds">,
): void {
  state.obligationResults = state.obligationResults.filter(
    (result) => !mission.obligationIds.includes(result.obligationId),
  );
  for (const chain of state.chains)
    if (mission.chainIds.includes(chain.id)) {
      chain.status = "open";
      chain.evidence = undefined;
      chain.landedIds = undefined;
    }
}

export function createEngagementState(plan: EngagementPlan): EngagementState {
  return {
    version: 2,
    planHash: createHash("sha256").update(JSON.stringify(plan)).digest("hex"),
    revision: 0,
    missions: plan.missions.map((mission) => ({
      ...mission,
      attempt: 0,
      chainIds: [],
      workerId: `engagement-worker-${createHash("sha256").update(mission.id).digest("hex").slice(0, 20)}`,
      status: "pending",
    })),
    coverage: [],
    reportedFindings: [],
    landed: [],
    obligations: plan.coverageObligations,
    obligationResults: [],
    chains: [],
    additionalObjectives: [],
  };
}

export function engagementPairs(
  plan: EngagementPlan,
  state?: EngagementState,
): EngagementPair[] {
  return [
    ...new Map(
      [
        ...plan.missions.flatMap((mission) => mission.assignments),
        ...(state?.missions.flatMap((mission) => mission.assignments) ?? []),
        ...(state?.additionalObjectives.map(({ targetId, objectiveId }) => ({
          targetId,
          objectiveId,
        })) ?? []),
      ].map((pair) => [pairKey(pair), pair]),
    ).values(),
  ];
}

export function isEngagementTerminal(
  plan: EngagementPlan,
  state: EngagementState,
): boolean {
  const covered = new Set(state.coverage.map(pairKey));
  const resolved = new Set(
    state.obligationResults.map((result) => result.obligationId),
  );
  return (
    engagementPairs(plan, state).every((pair) => covered.has(pairKey(pair))) &&
    state.obligations.every((obligation) => resolved.has(obligation.id)) &&
    state.chains.every((chain) => chain.status !== "open") &&
    state.missions.every(
      (mission) =>
        mission.status === "completed" ||
        mission.status === "cancelled" ||
        (mission.status === "failed" &&
          mission.assignments.every((pair) => covered.has(pairKey(pair)))),
    )
  );
}

export function submitEngagementResult(
  state: EngagementState,
  missionId: string,
  attempt: number,
  response: unknown,
): void {
  const mission = state.missions.find((item) => item.id === missionId);
  if (!mission || mission.status !== "running" || mission.attempt !== attempt)
    throw new Error("Worker attempt is no longer active");
  const result = MissionResultSchema.parse(response);
  const assigned = new Set(mission.assignments.map(pairKey));
  const seen = new Set<string>();
  for (const cell of result.coverage) {
    const key = pairKey(cell);
    if (!assigned.has(key) || seen.has(key))
      throw new Error(`Invalid mission coverage: ${key}`);
    seen.add(key);
  }
  if (seen.size !== assigned.size)
    throw new Error(
      `Mission ${missionId} omitted ${assigned.size - seen.size} assigned pairs`,
    );
  mission.result = result;
  mission.status = "submitted";
}

export function pairKey(pair: EngagementPair): string {
  return `${pair.targetId}\u0000${pair.objectiveId}`;
}

export function engagementStatePage(
  plan: EngagementPlan,
  state: EngagementState,
  offset = 0,
  limit = 20,
) {
  const pairs = engagementPairs(plan, state);
  const covered = new Set(state.coverage.map(pairKey));
  const open = pairs.filter((pair) => !covered.has(pairKey(pair)));
  const results = new Map(
    state.obligationResults.map((result) => [result.obligationId, result]),
  );
  const next = (total: number) =>
    offset + limit < total ? offset + limit : null;
  return {
    missions: state.missions.slice(offset, offset + limit).map((mission) => ({
      id: mission.id,
      parentId: mission.parentId,
      workerId: mission.workerId,
      attempt: mission.attempt,
      status: mission.status,
      purpose: mission.purpose.slice(0, 240),
      progress: mission.progress?.slice(0, 240),
    })),
    totalMissions: state.missions.length,
    nextMissionOffset: next(state.missions.length),
    completedPairs: covered.size,
    totalPairs: pairs.length,
    openPairs: open
      .slice(offset, offset + limit)
      .map(({ targetId, objectiveId }) => ({ targetId, objectiveId })),
    nextOffset: next(open.length),
    obligations: state.obligations
      .slice(offset, offset + limit)
      .map((item) => ({
        id: item.id,
        kind: item.kind,
        description: item.description.slice(0, 240),
        status: results.get(item.id)?.status ?? "unresolved",
      })),
    totalObligations: state.obligations.length,
    resolvedObligations: results.size,
    nextObligationOffset: next(state.obligations.length),
    chains: state.chains.slice(offset, offset + limit).map((chain) => ({
      id: chain.id,
      status: chain.status,
      hypothesis: chain.hypothesis.slice(0, 240),
    })),
    totalChains: state.chains.length,
    openChains: state.chains.filter((chain) => chain.status === "open").length,
    nextChainOffset: next(state.chains.length),
  };
}
