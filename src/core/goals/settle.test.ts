import { describe, expect, it } from "vitest";
import type { CitedPart, GoalHost, GoalNext, ScheduleResult } from "./host";
import { wrapUpMessage } from "./prompt";
import {
  type Citations,
  decideGoalAfterTurn,
  outputContainsQuote,
  scheduleGoalNext,
  settleGoalTurn,
  type TurnFacts,
  turnFactsFromMessages,
} from "./settle";
import type { EvidenceRef } from "./tool";
import { createGoal, type Goal, goalMaxRoundsSchema } from "./types";

const goal = (over: Partial<Goal> = {}): Goal => ({
  ...createGoal({ sessionId: "ses_1", objective: "make the tests pass" }),
  ...over,
});

const facts = (over: Partial<TurnFacts> = {}): TurnFacts => ({
  outcome: "completed",
  automatic: true,
  toolCallCount: 2,
  heldCallCount: 0,
  updateCall: null,
  ...over,
});

const good: CitedPart = {
  address: "local:ses_1/m4/p0",
  succeeded: true,
  inGoalWindow: true,
};

const ok: EvidenceRef = { tool: "execute_command", quote: "ok" };

const complete = (evidence: EvidenceRef[]) => ({
  status: "complete",
  summary: "done",
  evidence,
});

describe("decideGoalAfterTurn", () => {
  it("never completes a goal when the turn just ends", () => {
    const d = decideGoalAfterTurn(goal(), facts(), []);
    expect(d.goal?.status).toBe("active");
    expect(d.goal?.rounds).toBe(1);
    expect(d.next?.kind).toBe("continue");
    expect(d.next?.message).toMatch(/^Continue working toward the goal\./);
  });

  it("completes on a claim whose citations check out, storing the matching address", () => {
    const d = decideGoalAfterTurn(
      goal(),
      facts({ updateCall: complete([ok]) }),
      [{ ref: ok, candidates: [{ ...good, succeeded: false }, good] }],
    );
    expect(d.goal?.status).toBe("complete");
    expect(d.goal?.completion?.evidence).toEqual(["local:ses_1/m4/p0"]);
    expect(d.next).toBeNull();
  });

  it.each<[string, Citations, string]>([
    ["no citations", [], "it cites no evidence"],
    [
      "a quote that matches nothing",
      [{ ref: ok, candidates: [] }],
      'no execute_command output containing "ok" was found',
    ],
    [
      "only failed calls",
      [{ ref: ok, candidates: [{ ...good, succeeded: false }] }],
      "is from a failed call",
    ],
    [
      "only results from before the goal",
      [{ ref: ok, candidates: [{ ...good, inGoalWindow: false }] }],
      "is from before the goal started",
    ],
  ])("rejects a claim with %s and says why", (_label, citations, problem) => {
    const d = decideGoalAfterTurn(
      goal(),
      facts({ updateCall: complete(citations.map((c) => c.ref)) }),
      citations,
    );
    expect(d.goal?.status).toBe("active");
    expect(d.next?.kind).toBe("continue");
    expect(d.next?.message).toContain(problem);
  });

  it("explains an update_goal call that does not match its schema", () => {
    const d = decideGoalAfterTurn(
      goal(),
      facts({ updateCall: { status: "complete", evidence: "[...]" } }),
      [],
    );
    expect(d.goal?.status).toBe("active");
    expect(d.next?.message).toContain("did not match its schema");
  });

  it("settles an agent block without asking for evidence", () => {
    const d = decideGoalAfterTurn(
      goal(),
      facts({ updateCall: { status: "blocked", summary: "needs a token" } }),
      [],
    );
    expect(d.goal).toMatchObject({
      status: "blocked",
      reason: "agent_blocked",
      detail: "needs a token",
    });
    expect(d.next).toBeNull();
  });

  it("blocks a failed turn without a wrap-up", () => {
    const d = decideGoalAfterTurn(
      goal(),
      facts({ outcome: "error", error: "boom" }),
      [],
    );
    expect(d.goal).toMatchObject({
      status: "blocked",
      reason: "turn_failed",
      detail: "boom",
    });
    expect(d.next).toBeNull();
  });

  it("leaves the goal alone when the operator stopped the turn", () => {
    expect(
      decideGoalAfterTurn(goal(), facts({ outcome: "cancelled" }), []),
    ).toEqual({ goal: null, next: null });
  });

  it("waits without scheduling while a call is held for the operator", () => {
    const d = decideGoalAfterTurn(goal(), facts({ heldCallCount: 1 }), []);
    expect(d.goal?.status).toBe("active");
    expect(d.next).toBeNull();
  });

  it.each<[string, Partial<Goal>, Partial<TurnFacts>, string]>([
    ["the round limit", { rounds: 49 }, {}, "rounds"],
    [
      "the stall stop",
      { stalledRounds: 2 },
      { toolCallCount: 0 },
      "no_progress",
    ],
  ])("settles %s as blocked first, then asks for one wrap-up turn", (_label, state, turn, reason) => {
    const d = decideGoalAfterTurn(goal(state), facts(turn), []);
    expect(d.goal).toMatchObject({ status: "blocked", reason });
    expect(d.next?.kind).toBe("wrap_up");
    expect(d.next?.message).toMatch(/^The goal stopped: /);
  });

  it("does not count an operator turn without tool calls as a stall", () => {
    const d = decideGoalAfterTurn(
      goal({ stalledRounds: 2 }),
      facts({ automatic: false, toolCallCount: 0 }),
      [],
    );
    expect(d.goal).toMatchObject({ status: "active", stalledRounds: 0 });
  });

  it("accepts a valid completion on the last round", () => {
    const d = decideGoalAfterTurn(
      goal({ rounds: 49 }),
      facts({ updateCall: complete([ok]) }),
      [{ ref: ok, candidates: [good] }],
    );
    expect(d.goal?.status).toBe("complete");
  });
});

describe("wrapUpMessage", () => {
  it("names the limit that stopped the goal, in the right number", () => {
    expect(
      wrapUpMessage({
        ...goal(),
        status: "blocked",
        reason: "rounds",
        maxRounds: 1,
      }),
    ).toContain("the limit of 1 round.");
    expect(
      wrapUpMessage({ ...goal(), status: "blocked", reason: "rounds" }),
    ).toContain("the limit of 50 rounds.");
  });
});

describe("goal limits", () => {
  it.each([0, -1, 1.5, 201, "5"])("rejects maxRounds %s", (value) => {
    expect(goalMaxRoundsSchema.safeParse(value).success).toBe(false);
  });

  it("defaults to 50 rounds", () => {
    expect(goal().maxRounds).toBe(50);
  });
});

describe("outputContainsQuote", () => {
  it("matches across nested values and whitespace", () => {
    expect(
      outputContainsQuote({ stdout: "3  passed\n", exitCode: 0 }, "3 passed"),
    ).toBe(true);
    expect(outputContainsQuote({ stdout: "failed" }, "passed")).toBe(false);
  });
});

function memoryHost(
  initial: Goal,
  schedule: ScheduleResult = "scheduled",
): GoalHost & { goal: Goal; scheduled: GoalNext[]; reports: string[] } {
  const host = {
    goal: initial,
    scheduled: [] as GoalNext[],
    reports: [] as string[],
    async load() {
      return host.goal;
    },
    async update(goalId: string, next: Goal) {
      if (host.goal.id !== goalId || host.goal.status !== "active") return null;
      host.goal = next;
      return next;
    },
    async findEvidence(_goal: Goal, ref: EvidenceRef) {
      return ref.quote === "ok" ? [good] : [];
    },
    async scheduleTurn(next: GoalNext) {
      host.scheduled.push(next);
      return schedule;
    },
    report(saved: Goal, change: { from: string; to: string }) {
      host.reports.push(`${change.from}->${change.to}:${saved.reason}`);
    },
  };
  return host;
}

describe("settleGoalTurn", () => {
  it("settles before returning a wrap-up, and reports the change", async () => {
    const host = memoryHost(goal({ rounds: 49 }));
    const next = await settleGoalTurn(host, "ses_1", facts());
    expect(host.goal.status).toBe("blocked");
    expect(host.reports).toEqual(["active->blocked:rounds"]);
    expect(next?.kind).toBe("wrap_up");
  });

  it("does nothing once the goal is no longer active", async () => {
    const host = memoryHost({ ...goal(), status: "cancelled" });
    expect(await settleGoalTurn(host, "ses_1", facts())).toBeNull();
  });

  it("looks up the claim's evidence through the host", async () => {
    const host = memoryHost(goal());
    await settleGoalTurn(host, "ses_1", facts({ updateCall: complete([ok]) }));
    expect(host.goal.status).toBe("complete");
  });

  it("schedules nothing when another writer won the compare-and-set", async () => {
    const host = memoryHost(goal());
    host.update = async () => null;
    expect(await settleGoalTurn(host, "ses_1", facts())).toBeNull();
  });
});

describe("scheduleGoalNext", () => {
  const next = (id: string): GoalNext => ({
    kind: "continue",
    goalId: id,
    message: "Continue working toward the goal.",
  });

  it("blocks the goal when the host refuses a continuation", async () => {
    const host = memoryHost(goal(), { refused: "spend limit reached" });
    await scheduleGoalNext(host, "ses_1", next(host.goal.id));
    expect(host.goal).toMatchObject({
      status: "blocked",
      reason: "turn_refused",
      detail: "spend limit reached",
    });
  });

  it("leaves the goal alone when the operator took the turn", async () => {
    const host = memoryHost(goal(), "skipped");
    await scheduleGoalNext(host, "ses_1", next(host.goal.id));
    expect(host.goal.status).toBe("active");
  });
});

describe("turnFactsFromMessages", () => {
  it("counts tool calls and picks out the update_goal input", () => {
    const result = turnFactsFromMessages(
      [
        {
          role: "assistant",
          content: [
            { type: "tool-call", toolCallId: "a", toolName: "bash", input: {} },
            {
              type: "tool-call",
              toolCallId: "b",
              toolName: "update_goal",
              input: complete([ok]),
            },
          ],
        },
      ],
      { outcome: "completed", automatic: true, heldCallCount: 0 },
    );
    expect(result.toolCallCount).toBe(1);
    expect(result.updateCall).toEqual(complete([ok]));
  });
});
