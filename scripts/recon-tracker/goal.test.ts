import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { afterEach, beforeEach, expect, it } from "vitest";
import {
  type GeneralizedAttackSurfaceAgentInput,
  generalizedAttackSurfaceDefinition,
} from "../../src/core/agents/specialized/attackSurface/generalizedAgent";
import { readGoalFile } from "../../src/core/goals";
import type { SessionInfo } from "../../src/core/session";
import { runReconWithGoal } from "./goal";

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "recon-goal-"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));
const input = (): GeneralizedAttackSurfaceAgentInput => ({
  model: "anthropic/claude-opus-4.6",
  target: "https://app.example",
  session: {
    id: "ses_eval",
    rootPath: root,
    targets: ["https://app.example"],
    config: { prompt: "Model every supplied service using coverage.csv" },
  } as unknown as SessionInfo,
});
const call = (toolName: string, value: unknown): ModelMessage => ({
  role: "assistant",
  content: [
    { type: "tool-call", toolCallId: toolName, toolName, input: value },
  ],
});
const claim = () =>
  call("update_goal", {
    status: "complete",
    summary: "Ledger reviewed",
    evidence: [{ tool: "read_file", quote: "pending: 0" }],
  });
const evidence: ModelMessage = {
  role: "tool",
  content: [
    {
      type: "tool-result",
      toolCallId: "read_file",
      toolName: "read_file",
      output: { type: "text", value: "pending: 0" },
    },
  ],
};

it("continues after a report and rejected evidence, retaining native tools and the original goal", async () => {
  const opts = input();
  const turns = [
    [
      call("create_attack_surface_report", {
        summary: { analysisComplete: true },
      }),
    ],
    [claim()],
    [call("read_file", { path: "coverage.csv" }), evidence, claim()],
  ];
  const inputs: GeneralizedAttackSurfaceAgentInput[] = [];
  const goal = await runReconWithGoal(opts, (definition, options) => {
    const turn = turns[inputs.length];
    expect(turn).toBeDefined();
    inputs.push(options);
    assert(definition.createState && definition.system && definition.stopWhen);
    const state = definition.createState(options);
    expect(definition.activeTools(options, state)).toEqual([
      ...generalizedAttackSurfaceDefinition.activeTools(options, state),
      "update_goal",
    ]);
    expect(definition.system(options, state)).toContain(
      opts.session.config?.prompt,
    );
    return {
      streamResult: { response: Promise.resolve({ messages: turn }) },
      consume: async () => {
        const stops = definition.stopWhen?.(options, state);
        assert(stops);
        expect(Array.isArray(stops)).toBe(true);
        for (const stop of Array.isArray(stops) ? stops : [stops])
          expect(
            await stop({
              steps: [
                { toolCalls: [{ toolName: "create_attack_surface_report" }] },
              ],
            } as never),
          ).toBe(false);
        writeFileSync(
          join(root, "messages.json"),
          JSON.stringify([
            ...(options.messages ?? [
              { role: "user", content: "initial scope" },
            ]),
            ...turn,
          ]),
        );
      },
    };
  });
  expect(goal.status).toBe("complete");
  expect(goal.rounds).toBe(3);
  expect(goal.completion?.evidence).toHaveLength(1);
  expect(JSON.stringify(inputs[1].messages)).toContain(
    "create_attack_surface_report",
  );
  expect(JSON.stringify(inputs[2].messages)).toContain("no read_file output");
  expect(readGoalFile(root)).toEqual(goal);
});

it("uses the native no-progress limit and performs its final wrap-up turn", async () => {
  let rounds = 0;
  const goal = await runReconWithGoal(input(), (definition, options) => {
    rounds++;
    if (rounds === 5) {
      assert(definition.createState);
      expect(JSON.stringify(options.messages)).toContain("The goal stopped");
      expect(
        definition.activeTools(options, definition.createState(options)),
      ).not.toContain("update_goal");
    }
    return {
      streamResult: { response: Promise.resolve({ messages: [] }) },
      consume: async () => {
        writeFileSync(
          join(root, "messages.json"),
          JSON.stringify(options.messages ?? []),
        );
      },
    };
  });
  expect(rounds).toBe(5);
  expect(goal.status).toBe("blocked");
  expect(goal.reason).toBe("no_progress");
});

it("records provider failure as blocked and propagates the original failure", async () => {
  await expect(
    runReconWithGoal(input(), () => ({
      streamResult: { response: Promise.resolve({ messages: [] }) },
      consume: async () => {
        throw new Error("provider unavailable");
      },
    })),
  ).rejects.toThrow("provider unavailable");
  expect(readGoalFile(root)).toMatchObject({
    status: "blocked",
    reason: "turn_failed",
  });
});

it("preserves an active goal on operator cancellation", async () => {
  const controller = new AbortController();
  await expect(
    runReconWithGoal({ ...input(), abortSignal: controller.signal }, () => ({
      streamResult: { response: Promise.resolve({ messages: [] }) },
      consume: async () => {
        controller.abort(new Error("operator stopped"));
      },
    })),
  ).rejects.toThrow("operator stopped");
  expect(readGoalFile(root)?.status).toBe("active");
});
