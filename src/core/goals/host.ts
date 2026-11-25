import type { EvidenceRef } from "./tool";
import type { EvidenceAddress, Goal, GoalStatus } from "./types";

/** A tool result in the goal's session (or a subagent session under it). */
export interface CitedPart {
  /** Canonical address; always what gets stored. */
  address: EvidenceAddress;
  /** The tool completed rather than failed. */
  succeeded: boolean;
  /** Produced after the goal started. */
  inGoalWindow: boolean;
}

export type GoalNext =
  | { kind: "continue"; goalId: string; message: string }
  /** The goal is already settled as blocked; one final ordinary turn. */
  | { kind: "wrap_up"; goalId: string; message: string };

export type ScheduleResult = "scheduled" | "skipped" | { refused: string };

/** What a host supplies so Apex can run goals: storage, citation lookup and scheduling. */
export interface GoalHost {
  /** The session's current goal, live or settled. */
  load(sessionId: string): Promise<Goal | null>;
  /** Compare-and-set: writes `next` only while the stored goal with this id is still active. */
  update(goalId: string, next: Goal): Promise<Goal | null>;
  /** Tool results named `ref.tool` whose output matches with `outputContainsQuote`, newest first. */
  findEvidence(goal: Goal, ref: EvidenceRef): Promise<CitedPart[]>;
  /** "skipped" when the operator already took the turn or the goal moved on. */
  scheduleTurn(next: GoalNext): Promise<ScheduleResult>;
  /** Told after every status change. */
  report(goal: Goal, change: { from: GoalStatus; to: GoalStatus }): void;
}
