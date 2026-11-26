import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createFileGoalHost, readGoalFile, writeGoalFile } from "./fileHost";
import { kickoffMessage } from "./prompt";
import { createGoal, endGoal } from "./types";

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "goal-"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const goal = createGoal({ sessionId: "ses_1", objective: "write docs" });

function messages(list: ModelMessage[]) {
  writeFileSync(join(root, "messages.json"), JSON.stringify(list));
}

const result = (stdout: string, error = false): ModelMessage => ({
  role: "tool",
  content: [
    {
      type: "tool-result",
      toolCallId: stdout,
      toolName: "execute_command",
      output: error
        ? { type: "error-text", value: stdout }
        : { type: "json", value: { stdout, exitCode: 0 } },
    },
  ],
});

const host = () =>
  createFileGoalHost({
    sessionRoot: root,
    scheduleTurn: () => "scheduled",
    report: () => {},
  });

const ref = (quote: string) => ({ tool: "execute_command", quote });

describe("file goal host", () => {
  it("round-trips the goal and refuses to write over a settled one", async () => {
    writeGoalFile(root, goal);
    expect(await host().load("ses_1")).toEqual(goal);

    writeGoalFile(root, endGoal(goal, "cancelled", "ended_by_operator", null));
    expect(await host().update(goal.id, { ...goal, rounds: 1 })).toBeNull();
    expect(readGoalFile(root)?.status).toBe("cancelled");
  });

  it("finds matching tool results newest first, flagging failures and the goal window", async () => {
    messages([
      result("tests ok before"),
      { role: "user", content: kickoffMessage(goal) },
      result("tests ok failed", true),
      result("tests ok after"),
    ]);
    expect(await host().findEvidence(goal, ref("tests ok"))).toEqual([
      { address: "local:ses_1/m3/p0", succeeded: true, inGoalWindow: true },
      { address: "local:ses_1/m2/p0", succeeded: false, inGoalWindow: true },
      { address: "local:ses_1/m0/p0", succeeded: true, inGoalWindow: false },
    ]);
    expect(await host().findEvidence(goal, ref("nothing like it"))).toEqual([]);
    expect(
      await host().findEvidence(goal, { tool: "read_file", quote: "ok" }),
    ).toEqual([]);
  });

  it("keeps evidence before a kickoff out of the goal window when clients append context", async () => {
    messages([
      result("old proof"),
      {
        role: "user",
        content: `${kickoffMessage(goal)}\n\nAttached files: scope.csv at /session/attachments/scope.csv`,
      },
      result("new proof"),
      { role: "user", content: `${kickoffMessage(goal)} about something else` },
    ]);
    expect(await host().findEvidence(goal, ref("proof"))).toEqual([
      { address: "local:ses_1/m2/p0", succeeded: true, inGoalWindow: true },
      { address: "local:ses_1/m0/p0", succeeded: true, inGoalWindow: false },
    ]);
  });

  it("flags a command that exited nonzero inside an ordinary result", async () => {
    messages([
      { role: "user", content: kickoffMessage(goal) },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "c1",
            toolName: "execute_command",
            output: {
              type: "json",
              value: {
                success: false,
                stdout: "2 passed, 1 failed",
                exitCode: 1,
              },
            },
          },
        ],
      },
    ]);
    expect(await host().findEvidence(goal, ref("2 passed"))).toMatchObject([
      { succeeded: false },
    ]);
  });

  it("treats every remaining message as in the window once compaction dropped the kickoff", async () => {
    messages([result("kept")]);
    expect(await host().findEvidence(goal, ref("kept"))).toMatchObject([
      { inGoalWindow: true },
    ]);
  });
});
