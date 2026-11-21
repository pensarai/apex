import { randomUUID } from "node:crypto";
import { type ToolSet, tool } from "ai";
import { z } from "zod";
import type { EngagementJournal } from "./engagementJournal";
import { type EngagementTarget, pairKey } from "./engagementPlan";
import {
  ChainHypothesisSchema,
  type EngagementState,
  reopenMissionCoverage,
} from "./engagementState";

const Id = z.string().min(1).max(120);
const Text = z.string().trim().min(1);
const MissionInput = z.object({
  id: Id,
  purpose: Text,
  assignments: z
    .array(z.object({ targetId: Id, objectiveId: Id }))
    .min(1)
    .max(100),
  objectives: z
    .array(z.object({ targetId: Id, objectiveId: Id, text: Text }))
    .default([]),
  dependsOn: z.array(Id).default([]),
  parentId: Id.optional(),
  obligationIds: z.array(Id).default([]),
  chainIds: z.array(Id).default([]),
});

export function createCoordinationTools(options: {
  state: EngagementState;
  targets: EngagementTarget[];
  allowed: Set<string>;
  save(): void;
  schedule(): void;
  cancel(id: string): Promise<void>;
  journal: Pick<EngagementJournal, "append">;
  parentId?: string;
  attempt?: number;
}): ToolSet {
  const { state, targets, allowed, save, schedule, cancel, journal, parentId } =
    options;
  const sender = parentId
    ? (state.missions.find((item) => item.id === parentId)?.workerId ??
      parentId)
    : "engagement-lead";
  const notify = (text: string) =>
    journal.append({
      kind: "mail",
      from: sender,
      to: "engagement-lead",
      missionId: parentId,
      text,
    });
  const mission = (id: string) => {
    const record = state.missions.find((item) => item.id === id);
    if (!record) throw new Error(`Unknown mission: ${id}`);
    return record;
  };
  const assertWorkerActive = () => {
    if (
      parentId &&
      (mission(parentId).status !== "running" ||
        (options.attempt !== undefined &&
          mission(parentId).attempt !== options.attempt))
    )
      throw new Error("Worker attempt is no longer active");
  };
  const validate = (input: z.infer<typeof MissionInput>) => {
    assertWorkerActive();
    const parent = parentId
      ? mission(parentId)
      : input.parentId
        ? mission(input.parentId)
        : undefined;
    const permitted = parentId
      ? new Set(parent?.assignments.map((pair) => pair.targetId))
      : allowed;
    if (
      input.assignments.some((pair) => !permitted.has(pair.targetId)) ||
      input.objectives.some((pair) => !permitted.has(pair.targetId))
    )
      throw new Error("Mission contains an out-of-scope target");
    const referencedTargets = targets.filter((target) =>
      input.assignments.some((pair) => pair.targetId === target.id),
    );
    if (
      referencedTargets.length > 1 &&
      referencedTargets.some((target) => target.grpc)
    )
      throw new Error(
        "A gRPC mission must contain one target; coordinate separate missions through a chain",
      );
    const known = new Map([
      ...targets.flatMap((target) =>
        target.objectives.map(
          (objective) =>
            [
              pairKey({ targetId: target.id, objectiveId: objective.id }),
              objective.text,
            ] as const,
        ),
      ),
      ...state.additionalObjectives.map(
        (objective) => [pairKey(objective), objective.text] as const,
      ),
    ]);
    const additions = new Set<string>();
    for (const objective of input.objectives) {
      const key = pairKey(objective);
      if (
        (known.has(key) && known.get(key) !== objective.text) ||
        additions.has(key)
      )
        throw new Error(`Cannot redefine objective: ${objective.objectiveId}`);
      known.set(key, objective.text);
      additions.add(key);
    }
    const pairs = new Set<string>();
    for (const pair of input.assignments) {
      const key = pairKey(pair);
      if (!known.has(key) || pairs.has(key))
        throw new Error("Unknown or duplicate mission assignment");
      pairs.add(key);
    }
    if (input.objectives.some((pair) => !pairs.has(pairKey(pair))))
      throw new Error("New objectives must be assigned to this mission");
    for (const id of input.obligationIds)
      if (!state.obligations.some((item) => item.id === id))
        throw new Error(`Unknown obligation: ${id}`);
    for (const id of input.chainIds)
      if (!state.chains.some((item) => item.id === id))
        throw new Error(`Unknown or closed chain: ${id}`);
    const ancestors = new Set<string>();
    for (
      let ancestor = parent;
      ancestor;
      ancestor = ancestor.parentId ? mission(ancestor.parentId) : undefined
    ) {
      if (ancestor.id === input.id || ancestors.has(ancestor.id))
        throw new Error("Subtask hierarchy cycle");
      ancestors.add(ancestor.id);
    }
    const visit = (id: string, seen = new Set<string>()) => {
      if (ancestors.has(id))
        throw new Error("Subtask dependency would deadlock its parent");
      if (id === input.id) throw new Error("Mission dependency cycle");
      if (seen.has(id)) return;
      seen.add(id);
      for (const dependency of mission(id).dependsOn) visit(dependency, seen);
    };
    for (const id of input.dependsOn) visit(id);
    // Parents cannot land before their subtasks, so children cannot wait on an ancestor.
    for (
      let ancestor = parent;
      ancestor;
      ancestor = ancestor.parentId ? mission(ancestor.parentId) : undefined
    ) {
      if (ancestor.id === input.id || input.dependsOn.includes(ancestor.id))
        throw new Error("Subtask dependency would deadlock its parent");
    }
    return parent;
  };
  const addObjectives = (input: z.infer<typeof MissionInput>) => {
    for (const objective of input.objectives)
      if (
        !state.additionalObjectives.some(
          (item) => pairKey(item) === pairKey(objective),
        ) &&
        !targets.some(
          (target) =>
            target.id === objective.targetId &&
            target.objectives.some((item) => item.id === objective.objectiveId),
        )
      )
        state.additionalObjectives.push(objective);
  };
  const create = tool({
    description: parentId
      ? "Add a focused subtask within this mission's target scope. It uses the engagement's shared concurrency budget."
      : "Create an adaptive mission or subtask, including new objectives across approved targets. Link boundary obligations and chain hypotheses when relevant.",
    inputSchema: MissionInput,
    execute: async (input) => {
      if (state.missions.some((item) => item.id === input.id))
        throw new Error(`Mission already exists: ${input.id}`);
      const parent = validate(input);
      addObjectives(input);
      reopenMissionCoverage(state, input);
      state.missions.push({
        ...input,
        parentId: parent?.id,
        status: "pending",
        attempt: 0,
        workerId: `engagement-worker-${randomUUID()}`,
      });
      save();
      notify(`Created mission ${input.id}: ${input.purpose}`);
      schedule();
      return { missionId: input.id, status: "pending" };
    },
  });
  const common: ToolSet = {
    read_engagement_tasks: tool({
      description:
        "Read the shared mission/subtask list and lead-accepted landed ledger.",
      inputSchema: z.object({
        offset: z.number().int().min(0).default(0),
        limit: z.number().int().min(1).max(50).default(20),
      }),
      execute: async ({ offset, limit }) =>
        structuredClone({
          missions: state.missions.slice(offset, offset + limit),
          landed: state.landed.slice(offset, offset + limit),
          totalMissions: state.missions.length,
          totalLanded: state.landed.length,
        }),
    }),
    propose_engagement_chain: tool({
      description:
        "Retain a cross-service attack hypothesis and its prerequisite evidence, even when individual weaknesses are low severity. The lead must assign validation work and close it.",
      inputSchema: ChainHypothesisSchema,
      execute: async (input) => {
        assertWorkerActive();
        if (input.targetIds.some((id) => !allowed.has(id)))
          throw new Error("Chain contains an out-of-scope target");
        if (state.chains.some((chain) => chain.id === input.id))
          throw new Error(`Chain already exists: ${input.id}`);
        state.chains.push({ ...input, status: "open" });
        save();
        notify(`New chain hypothesis ${input.id}: ${input.hypothesis}`);
        return { chainId: input.id };
      },
    }),
  };
  if (parentId)
    return {
      ...common,
      add_engagement_subtask: create,
      update_engagement_progress: tool({
        description: "Record progress or a blocker on your shared mission.",
        inputSchema: z.object({ text: Text }),
        execute: async ({ text }) => {
          assertWorkerActive();
          mission(parentId).progress = text;
          save();
          journal.append({
            kind: "progress",
            from: sender,
            missionId: parentId,
            text,
          });
          return { accepted: true };
        },
      }),
    };
  return {
    ...common,
    create_engagement_mission: create,
    revise_engagement_mission: tool({
      description:
        "Revise or reassign a stopped mission with a fresh worker. Cancel a running attempt first; earlier landed entries remain immutable.",
      inputSchema: MissionInput,
      execute: async (input) => {
        const record = mission(input.id);
        if (record.status === "running" || record.status === "submitted")
          throw new Error(
            "Cancel or review the current attempt before revising it",
          );
        const parent = validate(input);
        addObjectives(input);
        reopenMissionCoverage(state, input);
        Object.assign(record, input, {
          parentId: parent?.id,
          status: "pending",
          workerId: `engagement-worker-${randomUUID()}`,
          result: undefined,
          error: undefined,
        });
        save();
        schedule();
        return { accepted: true };
      },
    }),
    cancel_engagement_mission: tool({
      description:
        "Cancel a mission and drain its current worker before releasing its slot. Uncovered obligations remain open.",
      inputSchema: z.object({ missionId: Id, reason: Text }),
      execute: async ({ missionId, reason }) => {
        await cancel(missionId);
        mission(missionId).error = reason;
        save();
        return { accepted: true };
      },
    }),
    accept_engagement_result: tool({
      description:
        "Review a submitted attempt and append it to the lead-owned landed ledger. Inspect evidence and unresolved subtasks/chains before accepting.",
      inputSchema: z.object({
        missionId: Id,
        attempt: z.number().int().min(1),
        review: Text,
      }),
      execute: async ({ missionId, attempt, review }) => {
        const record = mission(missionId);
        const previous = state.landed.find(
          (entry) => entry.missionId === missionId && entry.attempt === attempt,
        );
        if (previous) return structuredClone(previous);
        if (
          record.status !== "submitted" ||
          record.attempt !== attempt ||
          !record.result
        )
          throw new Error("No matching submitted attempt to accept");
        if (
          state.missions.some(
            (item) =>
              item.parentId === missionId &&
              item.status !== "completed" &&
              item.status !== "cancelled",
          )
        )
          throw new Error("Review and land subtasks first");
        const landed = {
          id: randomUUID(),
          missionId,
          attempt,
          obligationIds: [...record.obligationIds],
          chainIds: [...record.chainIds],
          acceptedBy: "engagement-lead" as const,
          acceptedAt: new Date().toISOString(),
          review,
          result: structuredClone(record.result),
        };
        state.landed.push(landed);
        for (const cell of landed.result.coverage) {
          const index = state.coverage.findIndex(
            (item) => pairKey(item) === pairKey(cell),
          );
          if (index < 0) state.coverage.push(cell);
          else state.coverage[index] = cell;
        }
        state.reportedFindings = [
          ...new Set([
            ...state.reportedFindings,
            ...landed.result.reportedFindings,
          ]),
        ];
        record.status = "completed";
        save();
        schedule();
        return structuredClone(landed);
      },
    }),
    resolve_engagement_obligation: tool({
      description:
        "Close a threat-model obligation with lead-reviewed evidence. Tested outcomes require landed missions explicitly assigned to the obligation; blockers remain visible as incomplete coverage.",
      inputSchema: z.object({
        obligationId: Id,
        status: z.enum(["tested", "blocked"]),
        evidence: Text,
        landedIds: z.array(Id),
      }),
      execute: async (input) => {
        const obligation = state.obligations.find(
          (item) => item.id === input.obligationId,
        );
        if (!obligation) throw new Error("Unknown coverage obligation");
        const landed = input.landedIds.map((id) => {
          const entry = state.landed.find((item) => item.id === id);
          if (!entry || !entry.obligationIds.includes(input.obligationId))
            throw new Error(
              "Landed evidence is not assigned to this obligation",
            );
          return entry;
        });
        if (
          input.status === "tested" &&
          obligation.targetIds.some(
            (id) =>
              !landed.some((entry) =>
                entry.result.coverage.some(
                  (cell) => cell.targetId === id && cell.status === "tested",
                ),
              ),
          )
        )
          throw new Error(
            "Tested obligations require landed coverage of every affected target",
          );
        const index = state.obligationResults.findIndex(
          (item) => item.obligationId === input.obligationId,
        );
        if (index < 0) state.obligationResults.push(input);
        else state.obligationResults[index] = input;
        save();
        return { accepted: true };
      },
    }),
    resolve_engagement_chain: tool({
      description:
        "Close a chain with evidence from its landed validation missions. Blocked chains must explain missing prerequisites; they do not count as fully tested.",
      inputSchema: z.object({
        chainId: Id,
        status: z.enum(["validated", "disproved", "blocked"]),
        evidence: Text,
        landedIds: z.array(Id),
      }),
      execute: async ({ chainId, status, evidence, landedIds }) => {
        const chain = state.chains.find((item) => item.id === chainId);
        if (!chain) throw new Error("Unknown chain hypothesis");
        const entries = landedIds.map((id) => {
          const entry = state.landed.find((item) => item.id === id);
          if (!entry || !entry.chainIds.includes(chainId))
            throw new Error("Landed evidence is not assigned to this chain");
          return entry;
        });
        if (
          status !== "blocked" &&
          chain.targetIds.some(
            (id) =>
              !entries.some((entry) =>
                entry.result.coverage.some(
                  (cell) => cell.targetId === id && cell.status === "tested",
                ),
              ),
          )
        )
          throw new Error(
            "Chain closure requires landed validation across every affected target",
          );
        Object.assign(chain, { status, evidence, landedIds });
        save();
        return { accepted: true };
      },
    }),
  };
}
