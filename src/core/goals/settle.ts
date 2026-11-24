import type { ModelMessage } from "ai";
import type { CitedPart, GoalHost, GoalNext } from "./host";
import { continuationMessage, wrapUpMessage } from "./prompt";
import {
  type EvidenceRef,
  UPDATE_GOAL_TOOL_NAME,
  updateGoalInputSchema,
} from "./tool";
import { endGoal, type Goal } from "./types";

export interface TurnFacts {
  outcome: "completed" | "cancelled" | "error";
  /** Started by the goal loop rather than by the operator. */
  automatic: boolean;
  /** Tool calls in the turn, update_goal excluded. */
  toolCallCount: number;
  /** Calls left waiting on the operator (approvals, questions). */
  heldCallCount: number;
  /** Raw input of the turn's update_goal call, if any. */
  updateCall: unknown | null;
  error?: string;
}

export interface GoalDecision {
  /** The goal's next state, or null when it is unchanged. */
  goal: Goal | null;
  next: GoalNext | null;
}

/** One entry per cited ref, in order, with the host's matches. */
export type Citations = { ref: EvidenceRef; candidates: CitedPart[] }[];

const normalize = (text: string) => text.replace(/\s+/g, " ").trim();

function stringLeaves(value: unknown, out: string[]): string[] {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const v of value) stringLeaves(v, out);
  else if (value && typeof value === "object")
    for (const v of Object.values(value)) stringLeaves(v, out);
  return out;
}

/** The one matching rule every host uses: the quote appears in the output's text, whitespace-insensitive. */
export function outputContainsQuote(output: unknown, quote: string): boolean {
  return normalize(stringLeaves(output, []).join("\n")).includes(
    normalize(quote),
  );
}

/** The cited part, or why the citation fails. */
export function checkCitation(
  ref: EvidenceRef,
  candidates: CitedPart[],
): { part: CitedPart } | { problem: string } {
  const part = candidates.find((c) => c.succeeded && c.inGoalWindow);
  if (part) return { part };
  const cited = `${ref.tool} output containing "${ref.quote}"`;
  if (candidates.length === 0) return { problem: `no ${cited} was found` };
  if (candidates.some((c) => c.inGoalWindow))
    return { problem: `the ${cited} is from a failed call` };
  return { problem: `the ${cited} is from before the goal started` };
}

export function decideGoalAfterTurn(
  goal: Goal,
  facts: TurnFacts,
  citations: Citations,
  now: Date = new Date(),
): GoalDecision {
  if (goal.status !== "active" || facts.outcome === "cancelled")
    return { goal: null, next: null };
  if (facts.outcome === "error")
    return {
      goal: endGoal(
        goal,
        "blocked",
        "turn_failed",
        facts.error ?? "The turn failed",
        now,
      ),
      next: null,
    };

  const counted: Goal = { ...goal, rounds: goal.rounds + 1 };
  const call = updateGoalInputSchema.safeParse(facts.updateCall);
  let rejections: string[] = [];

  if (facts.updateCall !== null && !call.success)
    rejections = [
      `the update_goal call did not match its schema (${call.error.issues[0]?.message ?? "invalid input"})`,
    ];
  if (facts.updateCall !== null && call.success) {
    if (call.data.status === "blocked")
      return {
        goal: endGoal(
          counted,
          "blocked",
          "agent_blocked",
          call.data.summary,
          now,
        ),
        next: null,
      };
    const checked = citations.map(({ ref, candidates }) =>
      checkCitation(ref, candidates),
    );
    rejections =
      checked.length === 0
        ? ["it cites no evidence"]
        : checked.flatMap((c) => ("problem" in c ? [c.problem] : []));
    if (rejections.length === 0)
      return {
        goal: {
          ...endGoal(counted, "complete", null, null, now),
          completion: {
            summary: call.data.summary,
            evidence: [
              ...new Set(
                checked.flatMap((c) => ("part" in c ? [c.part.address] : [])),
              ),
            ],
            claimedAt: now.toISOString(),
          },
        },
        next: null,
      };
  }

  const stalled =
    facts.automatic && facts.toolCallCount === 0 ? goal.stalledRounds + 1 : 0;
  const progressed: Goal = { ...counted, stalledRounds: stalled };
  const limit =
    stalled >= goal.maxStalledRounds
      ? "no_progress"
      : progressed.rounds >= goal.maxRounds
        ? "rounds"
        : null;
  if (limit) {
    const settled = endGoal(progressed, "blocked", limit, null, now);
    return {
      goal: settled,
      next: {
        kind: "wrap_up",
        goalId: goal.id,
        message: wrapUpMessage(settled),
      },
    };
  }
  if (facts.heldCallCount > 0) return { goal: progressed, next: null };
  return {
    goal: progressed,
    next: {
      kind: "continue",
      goalId: goal.id,
      message: continuationMessage(rejections),
    },
  };
}

/** Settles the session's goal after a turn and returns the turn to start next, if any. */
export async function settleGoalTurn(
  host: GoalHost,
  sessionId: string,
  facts: TurnFacts,
): Promise<GoalNext | null> {
  const goal = await host.load(sessionId);
  if (!goal || goal.status !== "active") return null;

  const call = updateGoalInputSchema.safeParse(facts.updateCall);
  const refs =
    call.success && call.data.status === "complete" ? call.data.evidence : [];
  const citations: Citations = await Promise.all(
    refs.map(async (ref) => ({
      ref,
      candidates: await host.findEvidence(goal, ref),
    })),
  );

  const decision = decideGoalAfterTurn(goal, facts, citations);
  if (!decision.goal) return null;
  const saved = await host.update(goal.id, decision.goal);
  if (!saved) return null;
  if (saved.status !== goal.status)
    host.report(saved, { from: goal.status, to: saved.status });
  return decision.next;
}

/** Starts `next`; a refused continuation settles the goal as blocked. */
export async function scheduleGoalNext(
  host: GoalHost,
  sessionId: string,
  next: GoalNext,
): Promise<void> {
  const result = await host.scheduleTurn(next);
  if (typeof result === "string" || next.kind !== "continue") return;
  const goal = await host.load(sessionId);
  if (!goal || goal.id !== next.goalId || goal.status !== "active") return;
  const saved = await host.update(
    goal.id,
    endGoal(goal, "blocked", "turn_refused", result.refused),
  );
  if (saved) host.report(saved, { from: "active", to: "blocked" });
}

/** Builds turn facts from the messages a turn produced. */
export function turnFactsFromMessages(
  messages: ModelMessage[],
  base: Pick<TurnFacts, "outcome" | "automatic" | "heldCallCount" | "error">,
): TurnFacts {
  let toolCallCount = 0;
  let updateCall: unknown | null = null;
  for (const message of messages) {
    if (message.role !== "assistant" || typeof message.content === "string")
      continue;
    for (const part of message.content) {
      if (part.type !== "tool-call") continue;
      if (part.toolName === UPDATE_GOAL_TOOL_NAME) updateCall = part.input;
      else toolCallCount++;
    }
  }
  return { ...base, toolCallCount, updateCall };
}
