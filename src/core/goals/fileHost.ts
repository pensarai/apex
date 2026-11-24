import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import type { CitedPart, GoalHost, GoalNext, ScheduleResult } from "./host";
import { kickoffMessage } from "./prompt";
import { outputContainsQuote, outputSucceeded } from "./settle";
import type { EvidenceRef } from "./tool";
import { type Goal, goalSchema } from "./types";

const GOAL_FILE = "goal.json";

export function readGoalFile(sessionRoot: string): Goal | null {
  const path = join(sessionRoot, GOAL_FILE);
  if (!existsSync(path)) return null;
  return goalSchema.parse(JSON.parse(readFileSync(path, "utf8")));
}

export function writeGoalFile(sessionRoot: string, goal: Goal): void {
  const path = join(sessionRoot, GOAL_FILE);
  writeFileSync(`${path}.tmp`, JSON.stringify(goal, null, 2));
  renameSync(`${path}.tmp`, path);
}

function readMessages(sessionRoot: string): ModelMessage[] {
  const path = join(sessionRoot, "messages.json");
  if (!existsSync(path)) return [];
  return JSON.parse(readFileSync(path, "utf8")) as ModelMessage[];
}

function textOf(message: ModelMessage): string {
  if (typeof message.content === "string") return message.content;
  return message.content
    .map((part) => (part.type === "text" ? part.text : ""))
    .join("");
}

/** Index of the goal's kickoff message; 0 when compaction already dropped it, since everything left is newer. */
function goalWindowStart(messages: ModelMessage[], goal: Goal): number {
  const kickoff = kickoffMessage(goal);
  for (let i = messages.length - 1; i >= 0; i--) {
    const message = messages[i];
    if (message?.role === "user" && textOf(message) === kickoff) return i;
  }
  return 0;
}

/** Searches the root session's messages.json, newest first; subagent sessions are not searched. */
export function findLocalEvidence(
  sessionRoot: string,
  goal: Goal,
  ref: EvidenceRef,
): CitedPart[] {
  const messages = readMessages(sessionRoot);
  const windowStart = goalWindowStart(messages, goal);
  const found: CitedPart[] = [];
  for (let m = messages.length - 1; m >= 0; m--) {
    const message = messages[m];
    if (message?.role !== "tool") continue;
    message.content.forEach((part, p) => {
      if (part.type !== "tool-result" || part.toolName !== ref.tool) return;
      const output = "value" in part.output ? part.output.value : part.output;
      if (!outputContainsQuote(output, ref.quote)) return;
      found.push({
        address: `local:${goal.sessionId}/m${m}/p${p}`,
        succeeded:
          part.output.type !== "error-text" &&
          part.output.type !== "error-json" &&
          outputSucceeded(output),
        inGoalWindow: m >= windowStart,
      });
    });
  }
  return found;
}

/** The CLI host: the goal lives in the session directory and turns run in-process. */
export function createFileGoalHost(input: {
  sessionRoot: string;
  scheduleTurn: (next: GoalNext) => ScheduleResult;
  report: GoalHost["report"];
}): GoalHost {
  const { sessionRoot } = input;
  return {
    async load() {
      return readGoalFile(sessionRoot);
    },
    async update(goalId, next) {
      const current = readGoalFile(sessionRoot);
      if (!current || current.id !== goalId || current.status !== "active")
        return null;
      writeGoalFile(sessionRoot, next);
      return next;
    },
    async findEvidence(goal, ref) {
      return findLocalEvidence(sessionRoot, goal, ref);
    },
    async scheduleTurn(next) {
      return input.scheduleTurn(next);
    },
    report: input.report,
  };
}
