import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import {
  continuationMessage,
  createFileGoalHost,
  createGoal,
  endGoal,
  type Goal,
  kickoffMessage,
  readGoalFile,
  settleGoalTurn,
  writeGoalFile,
} from "../../../goals";
import type {
  GeneralizedAttackSurfaceAgentInput,
  GeneralizedAttackSurfaceResult,
} from "./generalizedAgent";
import {
  buildCredentialsBlock,
  buildGeneralizedAttackSurfacePrompt,
} from "./generalizedPrompts";
import {
  completionSnapshot,
  structuralGaps,
  targetScopeGaps,
} from "./reconCompletionChecks";
import { startUpdate } from "./reconUpdate";
import { loadAttackSurfaceResults } from "./types";

export interface ReconGoalOptions {
  objective: string;
  maxRounds?: number;
  workSteps?: number;
}

/** The host must replay model/tool work in order and rebuild scratch files before each attempt. */
export interface ReconGoalJournal {
  runStep<T>(key: string, run: () => Promise<T>): Promise<T>;
}

export class ReconGoalIncompleteError extends Error {
  constructor(public readonly goal: Goal) {
    super(
      `Recon goal ${goal.status}: ${goal.reason ?? "awaiting continuation"}. ${goal.detail ?? ""}`,
    );
    this.name = "ReconGoalIncompleteError";
  }
}

const REPORT_BINDING = "recon-goal-report.json";

export function bindGoalReport(root: string, goal: Goal): void {
  const report = loadAttackSurfaceResults(
    join(root, "attack-surface-results.json"),
  );
  writeFileSync(
    join(root, REPORT_BINDING),
    JSON.stringify({
      goalId: goal.id,
      snapshot: completionSnapshot(root, report),
    }),
  );
}

function reportGaps(root: string, goal: Goal, origins: string[]): string[] {
  if (
    !existsSync(join(root, "attack-surface-results.json")) ||
    !existsSync(join(root, REPORT_BINDING))
  )
    return [
      "Create a fresh attack-surface report for this goal after checking your work.",
    ];
  const report = loadAttackSurfaceResults(
    join(root, "attack-surface-results.json"),
  );
  const binding = JSON.parse(readFileSync(join(root, REPORT_BINDING), "utf8"));
  return [
    ...(report.summary.analysisComplete === true
      ? []
      : [
          "The report marks analysis incomplete. Finish the work and regenerate the report.",
        ]),
    ...structuralGaps(root),
    ...targetScopeGaps(report, origins),
    ...(binding.goalId !== goal.id ||
    binding.snapshot !== completionSnapshot(root, report)
      ? [
          "The topology changed after the report. Reconcile the current records and regenerate the report.",
        ]
      : []),
  ];
}

export async function runGoalRecon(
  input: GeneralizedAttackSurfaceAgentInput,
  createAgent: (input: GeneralizedAttackSurfaceAgentInput) => {
    consume(): Promise<GeneralizedAttackSurfaceResult>;
    abortAndDrain?(): Promise<void>;
  },
): Promise<GeneralizedAttackSurfaceResult> {
  const options = input.goal;
  if (!options) throw new Error("Recon goal options are required");
  if (
    options.workSteps !== undefined &&
    (!Number.isInteger(options.workSteps) || options.workSteps < 1)
  )
    throw new Error("Recon goal workSteps must be a positive integer");
  const journal = input.goalJournal;
  if (input.contextRecorder && !journal)
    throw new Error(
      "Recon goals currently require the local host; durable hosts must supply goal storage and replay scheduling before enabling this path",
    );
  const root = input.session.rootPath;
  const origins = [...new Set([input.target, ...input.session.targets])];
  const requested = createGoal({ sessionId: input.session.id, ...options });
  if (journal) {
    // Replay starts at the first model turn, not the last executor's local checkpoint.
    for (const file of [
      "goal.json",
      "recon-goal-input.json",
      "messages.json",
      REPORT_BINDING,
      "attack-surface-results.json",
    ])
      rmSync(join(root, file), { force: true });
  }
  const journalScope = {
    origins,
    update: input.update?.trigger ?? null,
    repositories: input.session.config?.connectedRepositories ?? [],
  };
  const initial = journal
    ? await journal.runStep("recon.goal.initialize", async () => ({
        goal: requested,
        scope: journalScope,
      }))
    : null;
  if (initial)
    assert.deepEqual(
      initial.scope,
      journalScope,
      "Recon goal scope changed during replay",
    );
  const savedGoal = initial?.goal ?? readGoalFile(root);
  let goal = savedGoal ?? requested;
  if (
    goal.sessionId !== input.session.id ||
    goal.objective !== requested.objective ||
    goal.maxRounds !== requested.maxRounds
  )
    throw new Error(
      "Recon goal changed during resume; start a new session for a different objective or budget",
    );
  const inputPath = join(root, "recon-goal-input.json");
  const scope = { origins, update: input.update ?? null };
  let updateBrief = input.updateBrief;
  if (savedGoal && !journal) {
    const savedInput = JSON.parse(readFileSync(inputPath, "utf8"));
    assert.deepEqual(
      savedInput.scope,
      scope,
      "Recon goal scope or update changed during resume",
    );
    updateBrief = savedInput.updateBrief;
  } else {
    if (input.update) updateBrief = startUpdate(input.update, root).brief;
    writeFileSync(inputPath, JSON.stringify({ scope, updateBrief }));
    writeGoalFile(root, goal);
  }
  const host = createFileGoalHost({
    sessionRoot: root,
    scheduleTurn: () => {
      throw new Error("Recon schedules goal turns inline");
    },
    report: () => {},
  });
  const readMessages = (): ModelMessage[] =>
    existsSync(join(root, "messages.json"))
      ? JSON.parse(readFileSync(join(root, "messages.json"), "utf8"))
      : (input.messages ?? []);
  const runTurn = async (message: string, wrapUp = false) => {
    const history = readMessages();
    const initial: ModelMessage[] = history.length
      ? history
      : [
          {
            role: "user",
            content: buildGeneralizedAttackSurfacePrompt(
              origins,
              input.session.config?.connectedRepositories ?? [],
              input.session.config?.prompt,
              undefined,
              updateBrief,
              buildCredentialsBlock(
                (
                  input.credentialManager ?? input.session.credentialManager
                )?.formatForPrompt(),
                input.session.config?.authenticationInstructions,
              ),
            ),
          },
        ];
    const agent = createAgent({
      ...input,
      updateBrief,
      harness: "general",
      goalTurn: goal,
      messages: [...initial, { role: "user", content: message }],
      stepLimit: wrapUp ? 1 : (options.workSteps ?? 100),
    });
    try {
      return await agent.consume();
    } finally {
      await agent.abortAndDrain?.();
    }
  };
  if (goal.status === "complete") {
    const gaps = reportGaps(root, goal, origins);
    if (gaps.length)
      throw new Error(
        `Completed recon goal has stale output: ${gaps.join("; ")}`,
      );
    const resultsPath = join(root, "attack-surface-results.json");
    const results = loadAttackSurfaceResults(resultsPath);
    return {
      results,
      targets: results.targets,
      resultsPath,
      assetsPath: join(root, "assets"),
      goal,
    };
  }
  if (goal.status !== "active") throw new ReconGoalIncompleteError(goal);
  const kickoff = kickoffMessage(goal);
  const hasKickoff = readMessages().some(
    (message) => message.role === "user" && message.content === kickoff,
  );
  let message = hasKickoff || goal.rounds > 0 ? continuationMessage() : kickoff;
  try {
    while (goal.status === "active") {
      input.abortSignal?.throwIfAborted();
      const result = await runTurn(message);
      input.abortSignal?.throwIfAborted();
      if (!result.goalTurnFacts)
        throw new Error("Recon goal turn did not return completion facts");
      const facts = result.goalTurnFacts;
      const settle = async () => {
        const gaps = reportGaps(root, goal, origins);
        const claim = facts.updateCall as { status?: string } | null;
        const next = await settleGoalTurn(host, input.session.id, {
          ...facts,
          ...(claim?.status === "complete" && gaps.length
            ? { updateCall: null }
            : {}),
        });
        const saved = await host.load(input.session.id);
        assert(saved, "Goal disappeared while settling a recon turn");
        return {
          goal: saved,
          next:
            next?.kind === "continue" && gaps.length
              ? {
                  ...next,
                  message: `${next.message}\nReport checks: ${gaps.join("; ")}`,
                }
              : next,
        };
      };
      const settled = journal
        ? await journal.runStep(`recon.goal.settle.${goal.rounds}`, settle)
        : await settle();
      goal = settled.goal;
      writeGoalFile(root, goal);
      const next = settled.next;
      if (goal.status === "complete") return { ...result, goal };
      if (next?.kind === "wrap_up") {
        await runTurn(next.message, true);
        break;
      }
      if (!next) break;
      message = next.message;
    }
  } catch (error) {
    // Operator cancellation leaves the goal resumable, as in Jorge's CLI host.
    if (!input.abortSignal?.aborted && goal.status === "active") {
      goal = endGoal(
        goal,
        "blocked",
        "turn_failed",
        error instanceof Error ? error.message : String(error),
      );
      await host.update(goal.id, goal);
    }
    throw error;
  }
  throw new ReconGoalIncompleteError(goal);
}
