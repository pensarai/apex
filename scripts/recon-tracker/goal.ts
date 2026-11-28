import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { type ModelMessage, stepCountIs } from "ai";
import { AgentRuntime } from "../../src/core/agents/agentRuntime";
import {
  type GeneralizedAttackSurfaceAgentInput,
  generalizedAttackSurfaceDefinition as recon,
} from "../../src/core/agents/specialized/attackSurface/generalizedAgent";
import {
  createFileGoalHost,
  createGoal,
  createUpdateGoalTool,
  type Goal,
  type GoalNext,
  goalPromptSection,
  goalStopCondition,
  readGoalFile,
  scheduleGoalNext,
  settleGoalTurn,
  turnFactsFromMessages,
  UPDATE_GOAL_TOOL_NAME,
  writeGoalFile,
} from "../../src/core/goals";
import { normalizeMessages, sessions } from "../../src/core/session";

interface GoalTurn {
  consume(): Promise<unknown>;
  streamResult: { response: PromiseLike<{ messages: ModelMessage[] }> };
}

export async function runReconWithGoal(
  input: GeneralizedAttackSurfaceAgentInput,
  createAgent: (
    definition: typeof recon,
    options: GeneralizedAttackSurfaceAgentInput,
  ) => GoalTurn = (definition, options) =>
    new AgentRuntime(definition, options),
): Promise<Goal> {
  const root = input.session.rootPath;
  assert(recon.system);
  const reconSystem = recon.system;
  if (readGoalFile(root))
    throw new Error("Goal evaluation requires a fresh session");
  const objective = input.session.config?.prompt;
  if (!objective) throw new Error("Goal evaluation requires an objective");
  let goal = createGoal({ sessionId: input.session.id, objective });
  writeGoalFile(root, goal);
  let scheduled: GoalNext | null = null;
  const host = createFileGoalHost({
    sessionRoot: root,
    scheduleTurn: (next) => {
      scheduled = next;
      return "scheduled";
    },
    report: () => {},
  });
  let messages: ModelMessage[] | undefined;
  let automatic = false;
  do {
    scheduled = null;
    const active = goal.status === "active";
    const definition: typeof recon = {
      ...recon,
      system: (opts, state) =>
        `${reconSystem(opts, state)}${active ? `\n\n${goalPromptSection(goal)}` : ""}`,
      activeTools: (opts, state) => [
        ...recon.activeTools(opts, state),
        ...(active ? [UPDATE_GOAL_TOOL_NAME] : []),
      ],
      extraTools: () =>
        active
          ? { [UPDATE_GOAL_TOOL_NAME]: createUpdateGoalTool() }
          : undefined,
      // A report is work product; only native goal settlement ends an active goal.
      stopWhen: () => [
        stepCountIs(10_000),
        ...(active ? [goalStopCondition] : []),
      ],
    };
    try {
      const agent = createAgent(definition, { ...input, messages });
      await agent.consume();
      if (input.abortSignal?.aborted) throw input.abortSignal.reason;
      if (active) {
        const response = await agent.streamResult.response;
        const next = await settleGoalTurn(
          host,
          input.session.id,
          turnFactsFromMessages(response.messages, {
            outcome: "completed",
            automatic,
            heldCallCount: 0,
          }),
        );
        if (next) await scheduleGoalNext(host, input.session.id, next);
      }
    } catch (error) {
      await settleGoalTurn(host, input.session.id, {
        outcome: input.abortSignal?.aborted ? "cancelled" : "error",
        automatic,
        heldCallCount: 0,
        toolCallCount: 0,
        updateCall: null,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
    const stored = readGoalFile(root);
    if (!stored) throw new Error("Goal disappeared during evaluation");
    goal = stored;
    const next = scheduled as GoalNext | null;
    if (next) {
      const retained = JSON.parse(
        readFileSync(join(root, "messages.json"), "utf8"),
      ) as ModelMessage[];
      messages = normalizeMessages([
        ...sessions.getResumeMessages(retained),
        { role: "user", content: next.message },
      ]);
      automatic = true;
    }
  } while (scheduled);
  return goal;
}
