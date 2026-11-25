import { mock } from "bun:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { testRender } from "@opentui/react/test-utils";
import { act } from "react";
import { AgentEventBus } from "../../../../core/eventBus";
import type { ApprovalGate } from "../../../../core/operator";
import type { SessionInfo } from "../../../../core/session";
import type { DisplayMessage } from "../../agent-display";

const scenario = process.argv[2];
assert.ok(scenario);
const rootPath = mkdtempSync(join(tmpdir(), "apex-plan-queue-"));
const session = {
  id: "queue-session",
  name: "Queue test",
  rootPath,
  targets: ["https://example.test"],
  config: {},
} as SessionInfo;
const noop = () => {};
let aborts = 0;
const modulePath = (path: string) => join(import.meta.dirname, path);
let input:
  | {
      onSubmit: (text: string) => void;
      status: string;
      placeholder: string;
      focused: boolean;
    }
  | undefined;
const currentInput = () => {
  assert.ok(input);
  return input;
};
let displayed: DisplayMessage[] = [];
let queued: { text: string }[] = [];
const runs: {
  prompt: string;
  system?: string;
  eventBus: AgentEventBus;
  approvalGate: ApprovalGate;
  finish: () => void;
}[] = [];

mock.module(modulePath("../../../../core/agents/offSecAgent/index.ts"), () => ({
  AgentEventBus,
  ALL_TOOL_NAMES: [],
  ASK_USER_QUESTIONS_TOOL_NAME: "ask_user_questions",
  PLAN_MODE_TOOL_NAMES: [],
  SKILL_TOOL_NAMES: [],
  buildBaseSystemPrompt: () => "Test system prompt",
}));
mock.module(modulePath("../../../../core/cli/reasoning.ts"), () => ({
  getSavedReasoning: () => undefined,
}));
mock.module(modulePath("../../../../core/ai/index.ts"), () => ({
  buildAuthConfig: () => ({}),
  compactedHistoryNotice: () => "",
  normalizeStepUsage: () => ({ inputTokens: 0, outputTokens: 0 }),
}));
mock.module(modulePath("../../../../core/api/index.ts"), () => ({
  createOffensiveSecurityAgentClient: () => ({
    abort: () => {
      aborts++;
    },
    run: async (options: {
      prompt: string;
      system?: string;
      eventBus: AgentEventBus;
      approvalGate: ApprovalGate;
      onSessionReady: (value: SessionInfo) => void;
    }) => {
      options.onSessionReady(session);
      await new Promise<void>((resolve) => {
        runs.push({
          prompt: options.prompt,
          system: options.system,
          eventBus: options.eventBus,
          approvalGate: options.approvalGate,
          finish: resolve,
        });
      });
      return {
        session,
        streamResult: { response: Promise.resolve({ messages: [] }) },
      };
    },
  }),
}));
mock.module(modulePath("../../../../core/session/index.ts"), () => ({
  normalizeMessages: (messages: unknown) => messages,
  getSessionRoot: () => rootPath,
  getResumeMessages: (messages: unknown) => messages,
  sessions: {
    getResumeMessages: (messages: unknown) => messages,
    updateOperatorSettings: async () => {},
  },
}));
mock.module(
  modulePath("../../../../core/integrations/wandb/upload.ts"),
  () => ({
    attachWandbToEventBus: async () => null,
  }),
);
const agent = {
  model: { id: "test-model", name: "Test" },
  setModel: noop,
  isModelUserSelected: true,
  setThinking: noop,
  setIsExecuting: noop,
  markExecuted: noop,
  setSessionCwd: noop,
  setReasoning: noop,
  usageStore: { beginNewSession: noop, enterSession: noop },
};
const config = { data: {} };
const command = {
  autocompleteOptions: [],
  commandOptionMap: new Map(),
  commandNames: [],
  executeCommand: noop,
  resolveSkillContent: noop,
  skillsRegistry: { list: () => [], buildCatalog: () => "" },
  skillsVersion: 0,
};
const route = { data: { type: "operator" }, navigate: noop };
const dialog = {
  stack: [],
  externalDialogOpen: false,
  replace: noop,
  clear: noop,
};
const focus = { refocusPromptIfNoActiveEditor: noop };
const herdr = { report: noop };
for (const [name, hook, value] of [
  ["agent", "useAgent", agent],
  ["config", "useConfig", config],
  ["command", "useCommand", command],
  ["route", "useRoute", route],
  ["dialog", "useDialog", dialog],
  ["focus", "useFocus", focus],
  ["herdr", "useHerdr", herdr],
  ["obfuscation", "useObfuscation", { enabled: false }],
] as const) {
  mock.module(modulePath(`../../../context/${name}.tsx`), () => ({
    [hook]: () => value,
  }));
}
mock.module(modulePath("../../../theme/index.ts"), () => ({
  useTheme: () => ({
    colors: {
      text: "#ffffff",
      textMuted: "#888888",
      error: "#ff0000",
      warning: "#ffff00",
    },
  }),
}));
mock.module(modulePath("../../chat/input-area.tsx"), () => ({
  InputArea: (props: NonNullable<typeof input>) => {
    input = props;
    return null;
  },
}));
mock.module(modulePath("../../chat/message-list.tsx"), () => ({
  MessageList: (props: { messages: DisplayMessage[] }) => {
    displayed = props.messages;
    return null;
  },
}));
mock.module(modulePath("../../chat/questions-form.tsx"), () => ({
  QuestionsForm: () => null,
}));
mock.module(modulePath("../../screenshot-modal.tsx"), () => ({
  collectScreenshotPaths: () => [],
  ScreenshotModal: () => null,
}));
mock.module(modulePath("../../shared/index.ts"), () => ({
  deriveApprovedActionLabel: () => "",
  isToolMessage: () => false,
}));
mock.module(modulePath("../queued-messages.tsx"), () => ({
  QueuedMessages: (props: { messages: { text: string }[] }) => {
    queued = props.messages;
    return null;
  },
}));
mock.module(modulePath("../subagent-status-bar.tsx"), () => ({
  SubagentStatusBar: () => null,
}));
mock.module(modulePath("../subagent-dialog.tsx"), () => ({
  default: () => null,
}));
mock.module(modulePath("../welcome-logo.tsx"), () => ({
  WELCOME_LOGO_HEIGHT: 0,
  WELCOME_LOGO_WIDTH: 0,
  WelcomeLogo: () => null,
}));
const { default: OperatorDashboard } = await import("../index.tsx");
const setup = await testRender(
  <OperatorDashboard
    initialConfig={{
      operatorMode: scenario === "queue-refine-waiting" ? "manual" : "plan",
    }}
  />,
  { width: 100, height: 30, exitOnCtrlC: false },
);
const settle = async () => {
  for (let i = 0; i < 4; i++) await act(async () => {});
  await act(setup.renderOnce);
};
const submit = async (text: string) => {
  await act(async () => currentInput().onSubmit(text));
  await settle();
};
const reviewedPlan =
  "# Reviewed Plan\nTest only the authorized public endpoint.";
const replacementPlan = "# Replacement Plan\nTest a different endpoint.";
const unreviewedPlan = "# Unreviewed Plan\nNever approved by the operator.";
const finish = async (index: number, plan?: string) => {
  await act(async () => {
    if (plan !== undefined) {
      writeFileSync(join(rootPath, "plan.md"), plan);
      runs[index].eventBus.emit("tool-result", {
        toolCallId: "plan",
        toolName: "submit_plan",
        result: { success: true },
      });
    }
    runs[index].finish();
  });
  await settle();
};
const press = async (key: string, modifiers?: { shift: boolean }) => {
  await act(async () => setup.mockInput.pressKey(key, modifiers));
  await settle();
};
try {
  await settle();
  await submit("Prepare a plan");
  assert.equal(runs.length, 1);
  if (scenario.startsWith("snapshot-")) {
    await finish(0, reviewedPlan);
    const reviewMessages = () =>
      displayed.filter((message) => message.isPlanReview);
    assert.equal(reviewMessages().at(-1)?.planContent, reviewedPlan);
    let expectedPlan = reviewedPlan;
    let expectedRuns = 2;
    if (scenario === "snapshot-deleted") {
      unlinkSync(join(rootPath, "plan.md"));
    } else if (scenario === "snapshot-changed") {
      writeFileSync(join(rootPath, "plan.md"), replacementPlan);
    } else {
      if (scenario === "snapshot-rejected") {
        await press("n");
        assert.equal(runs.length, 1);
      }
      await submit("Refine the plan");
      assert.equal(runs.length, 2);
      await finish(1, replacementPlan);
      assert.equal(reviewMessages().at(-1)?.planContent, replacementPlan);
      assert.equal(reviewMessages().length, 2);
      writeFileSync(join(rootPath, "plan.md"), unreviewedPlan);
      expectedPlan = replacementPlan;
      expectedRuns = 3;
    }
    await press("y");
    assert.equal(runs.length, expectedRuns);
    const approved = runs.at(-1);
    assert.ok(approved);
    assert.equal(approved.prompt, "Proceed with the approved plan.");
    assert.ok(
      approved.system?.includes(`<plan>\n${expectedPlan}\n</plan>`),
      "execution must use exactly the plan shown in review",
    );
    assert.ok(!approved.system?.includes(unreviewedPlan));
  } else {
    await submit("Queued follow-up");
    assert.deepEqual(
      queued.map(({ text }) => text),
      ["Queued follow-up"],
    );
    if (scenario === "queue-normal") {
      await submit("Second follow-up");
      await finish(0);
      assert.equal(runs[1].prompt, "Queued follow-up");
      assert.deepEqual(
        queued.map(({ text }) => text),
        ["Second follow-up"],
      );
      await finish(1);
      assert.equal(runs[2].prompt, "Second follow-up");
      assert.deepEqual(queued, []);
    } else if (scenario === "queue-approve-running") {
      writeFileSync(join(rootPath, "plan.md"), reviewedPlan);
      await act(async () => {
        runs[0].eventBus.emit("tool-result", {
          toolCallId: "old-plan",
          toolName: "submit_plan",
          result: { success: true },
        });
      });
      await press("TAB", { shift: true });
      assert.ok(displayed.some((message) => message.isPlanReview));
      await press("y");
      assert.equal(runs.length, 2);
      assert.equal(runs[1].prompt, "Proceed with the approved plan.");
      assert.equal(aborts, 1);
      await finish(0);
      assert.equal(runs.length, 2);
      assert.equal(currentInput().status, "running");
      await finish(1);
      assert.equal(
        displayed.filter((message) => message.isPlanReview).length,
        1,
        "execution must not reopen a previously approved plan",
      );
      assert.equal(runs.length, 3);
      assert.equal(runs[2].prompt, "Queued follow-up");
      assert.deepEqual(queued, []);
    } else if (scenario === "queue-refine-waiting") {
      const gate = runs[0].approvalGate;
      let pending: Promise<unknown> | undefined;
      await act(async () => {
        pending = gate
          .check("http_request", "pending-http", {})
          .catch((error) => error);
      });
      await settle();
      assert.equal(gate.getPendingApprovals().length, 1);
      writeFileSync(join(rootPath, "plan.md"), reviewedPlan);
      await press("TAB", { shift: true });
      await press("TAB", { shift: true });
      await press("TAB", { shift: true });
      assert.ok(displayed.some((message) => message.isPlanReview));
      await submit("Refine without the pending action");
      assert.equal(runs.length, 2);
      assert.equal(
        gate.getPendingApprovals().length,
        0,
        "review feedback must deny the previous pending action",
      );
      assert.ok(pending);
      const approvalResult = await pending;
      assert.ok(approvalResult instanceof Error);
      assert.equal(approvalResult.name, "ApprovalDeniedError");
      assert.deepEqual(
        queued.map(({ text }) => text),
        ["Queued follow-up"],
      );
    } else if (
      scenario === "queue-refine-running" ||
      scenario === "queue-stale-submission"
    ) {
      writeFileSync(join(rootPath, "plan.md"), reviewedPlan);
      if (scenario === "queue-stale-submission") {
        await act(async () => {
          runs[0].eventBus.emit("tool-result", {
            toolCallId: "old-plan",
            toolName: "submit_plan",
            result: { success: true },
          });
        });
      }
      await press("TAB", { shift: true });
      assert.ok(displayed.some((message) => message.isPlanReview));
      await submit("Refine the active plan");
      assert.equal(
        runs.length,
        2,
        "explicit review feedback must start a refinement run",
      );
      assert.equal(runs[1].prompt, "Refine the active plan");
      assert.equal(aborts, 1, "refinement must interrupt the previous run");
      assert.deepEqual(
        queued.map(({ text }) => text),
        ["Queued follow-up"],
      );
      await finish(0);
      assert.equal(
        runs.length,
        2,
        "stale completion must not dispatch the queue",
      );
      assert.equal(currentInput().status, "running");
      if (scenario === "queue-stale-submission") {
        await finish(1);
        assert.equal(currentInput().status, "idle");
        assert.equal(
          displayed.filter((message) => message.isPlanReview).length,
          1,
          "refinement without a new submission must not reopen the rejected plan",
        );
        assert.equal(runs.length, 2);
        assert.deepEqual(
          queued.map(({ text }) => text),
          ["Queued follow-up"],
        );
        await submit("Finish revising the plan");
        await finish(2, replacementPlan);
      } else {
        await finish(1, replacementPlan);
      }
      assert.equal(
        displayed.filter((message) => message.isPlanReview).at(-1)?.planContent,
        replacementPlan,
      );
      const expectedRuns = scenario === "queue-stale-submission" ? 3 : 2;
      assert.equal(runs.length, expectedRuns);
      assert.deepEqual(
        queued.map(({ text }) => text),
        ["Queued follow-up"],
      );
      await press("y");
      assert.equal(
        runs[expectedRuns].prompt,
        "Proceed with the approved plan.",
      );
      await finish(expectedRuns);
      assert.equal(runs.length, expectedRuns + 2);
      assert.equal(runs[expectedRuns + 1].prompt, "Queued follow-up");
      assert.deepEqual(queued, []);
    } else if (scenario === "queue-review-running") {
      await press("ARROW_UP");
      assert.equal(currentInput().focused, false);
      writeFileSync(join(rootPath, "plan.md"), reviewedPlan);
      await press("TAB", { shift: true });
      assert.ok(displayed.some((message) => message.isPlanReview));
      assert.equal(
        currentInput().focused,
        true,
        "opening review must leave feedback input available",
      );
      await press("ARROW_UP");
      await press("RETURN");
      assert.equal(
        runs.length,
        1,
        "queue shortcuts must not bypass visible review",
      );
      assert.deepEqual(
        queued.map(({ text }) => text),
        ["Queued follow-up"],
      );
    } else {
      await finish(0, reviewedPlan);
      assert.ok(displayed.some((message) => message.isPlanReview));
      assert.equal(
        runs.length,
        1,
        "queued directive must wait for the plan review decision",
      );
      assert.deepEqual(
        queued.map(({ text }) => text),
        ["Queued follow-up"],
      );
      if (scenario === "queue-approve") {
        await press("y");
        assert.deepEqual(
          runs.map(({ prompt }) => prompt),
          ["Prepare a plan", "Proceed with the approved plan."],
        );
        assert.deepEqual(
          queued.map(({ text }) => text),
          ["Queued follow-up"],
        );
        await finish(1);
        assert.deepEqual(
          runs.map(({ prompt }) => prompt),
          [
            "Prepare a plan",
            "Proceed with the approved plan.",
            "Queued follow-up",
          ],
        );
        assert.deepEqual(queued, []);
      } else {
        if (scenario === "queue-reject") {
          await press("n");
          assert.equal(
            runs.length,
            1,
            "rejecting the plan must wait for refinement, not consume old queued input",
          );
          assert.deepEqual(
            queued.map(({ text }) => text),
            ["Queued follow-up"],
          );
        }
        await submit("Refine the scope");
        assert.deepEqual(
          runs.map(({ prompt }) => prompt),
          ["Prepare a plan", "Refine the scope"],
        );
        await finish(1, replacementPlan);
        assert.equal(runs.length, 2);
        assert.deepEqual(
          queued.map(({ text }) => text),
          ["Queued follow-up"],
        );
      }
    }
  }
} finally {
  await act(async () => {
    for (const run of runs) run.approvalGate.denyAll();
    setup.renderer.destroy();
  });
  rmSync(rootPath, { recursive: true, force: true });
}
