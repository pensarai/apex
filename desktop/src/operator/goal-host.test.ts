import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { OffensiveSecurityAgentClientInput } from "../../../src/core/api";
import { config } from "../../../src/core/config";
import * as goals from "../../../src/core/goals";
import { isGoalControlMessage, readGoalFile } from "../../../src/core/goals";
import { planFilePath } from "../../../src/core/plan";
import { sessions } from "../../../src/core/session";
import { createOperatorHost } from "./host";

const sdk = vi.hoisted(() => ({ run: vi.fn(), abort: vi.fn() }));
vi.mock("../../../src/core/api", () => ({
  createOffensiveSecurityAgentClient: () => sdk,
}));
vi.mock("../../../src/core/integrations/wandb/upload", () => ({
  attachWandbToEventBus: async () => null,
}));
function call(
  toolName: string,
  input: unknown,
  output: string = "ok",
): ModelMessage[] {
  return [
    {
      role: "assistant",
      content: [{ type: "tool-call", toolCallId: toolName, toolName, input }],
    },
    {
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolCallId: toolName,
          toolName,
          output: { type: "text", value: output },
        },
      ],
    },
  ];
}
const blocked = () =>
  call("update_goal", {
    status: "blocked",
    summary: "Waiting for access",
    evidence: [],
  });
async function result(
  input: OffensiveSecurityAgentClientInput,
  messages: ModelMessage[] = [],
) {
  if (!input.session) throw new Error("Missing session");
  await writeFile(
    join(input.session.rootPath, "messages.json"),
    JSON.stringify([...(input.messages ?? []), ...messages]),
  );
  return { session: input.session, streamResult: { response: { messages } } };
}
function required<T>(value: T | undefined | null): T {
  if (value == null) throw new Error("Missing fixture value");
  return value;
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("desktop goal lifecycle", () => {
  let dir: string;
  let host: ReturnType<typeof createOperatorHost>;
  beforeEach(async () => {
    dir = await mkdtemp(join(os.tmpdir(), "apex-goals-"));
    vi.spyOn(os, "homedir").mockReturnValue(dir);
    vi.stubEnv("PENSAR_DATA_DIR", join(dir, ".pensar"));
    vi.spyOn(config, "get").mockResolvedValue({
      responsibleUseAccepted: true,
      localModelUrl: "http://127.0.0.1",
      localModelName: "fixture",
      selectedModelId: "fixture",
    });
    sdk.run.mockReset();
    sdk.abort.mockReset();
    host = createOperatorHost({
      cwd: () => dir,
      requireAcceptance() {},
      emit() {},
    });
  });
  afterEach(async () => {
    await host.close(true);
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    await rm(dir, { recursive: true, force: true });
  });
  const idle = () =>
    vi.waitFor(() => expect(host.requests.operatorState().status).toBe("idle"));
  it("starts a goal from an empty tab and verifies completion against persisted tool output", async () => {
    sdk.run.mockImplementation((input) =>
      result(input, [
        ...call("execute_command", { command: "test" }, "All 12 checks passed"),
        ...call("update_goal", {
          status: "complete",
          summary: "Verified",
          evidence: [{ tool: "execute_command", quote: "12 checks passed" }],
        }),
      ]),
    );
    await host.requests.operatorGoal({
      command: "Verify the fixture --rounds 4",
      mode: "auto",
    });
    await idle();
    const snapshot = host.requests.operatorState();
    expect(snapshot.goal).toMatchObject({
      objective: "Verify the fixture",
      status: "complete",
      rounds: 1,
      maxRounds: 4,
    });
    expect(snapshot.goal?.completion?.evidence[0]).toMatch(
      /^local:.*\/m\d+\/p\d+$/,
    );
    const input = sdk.run.mock.calls[0][0];
    expect(input.extraTools.update_goal).toBeDefined();
    expect(input.activeTools).toContain("update_goal");
    expect(input.system).toContain("Verify the fixture");
    expect(
      snapshot.messages.some((m) => m.content === "Goal: Verify the fixture"),
    ).toBe(true);
    expect(readGoalFile(input.session.rootPath)?.status).toBe("complete");
  });
  it("rejects unsupported completion claims, continues invisibly, then wraps up once at the round limit", async () => {
    sdk.run.mockImplementation((input) =>
      result(
        input,
        call("update_goal", {
          status: "complete",
          summary: "Done",
          evidence: [],
        }),
      ),
    );
    await host.requests.operatorGoal({ command: "Verify evidence --rounds 2" });
    await idle();
    expect(sdk.run).toHaveBeenCalledTimes(3);
    expect(sdk.run.mock.calls[1][0].prompt).toContain("no evidence");
    expect(sdk.run.mock.calls[2][0].extraTools).toBeUndefined();
    expect(host.requests.operatorState().goal).toMatchObject({
      status: "blocked",
      reason: "rounds",
      rounds: 2,
    });
    expect(
      host.requests.operatorState().messages.filter((m) => m.role === "user"),
    ).toHaveLength(1);
  });
  it("gives queued user messages priority over automatic continuation", async () => {
    const wait = deferred();
    sdk.run
      .mockImplementationOnce(async (input) => {
        await wait.promise;
        return result(input, call("execute_command", {}));
      })
      .mockImplementation((input) => result(input, blocked()));
    const started = await host.requests.operatorGoal({ command: "Inspect" });
    await vi.waitFor(() => expect(sdk.run).toHaveBeenCalledOnce());
    await host.requests.operatorAction({
      sessionId: required(started.sessionId),
      action: { type: "send", text: "Focus on login" },
    });
    wait.resolve();
    await idle();
    expect(sdk.run).toHaveBeenCalledTimes(2);
    expect(sdk.run.mock.calls[1][0].prompt).toBe("Focus on login");
  });
  it.each([
    "cancel",
    "clear",
  ] as const)("%s prevents a late response from scheduling another goal turn", async (operation) => {
    const wait = deferred();
    sdk.run.mockImplementation(async (input) => {
      await wait.promise;
      return result(input, call("execute_command", {}));
    });
    sdk.abort.mockImplementation(wait.resolve);
    const started = await host.requests.operatorGoal({ command: "Inspect" });
    await vi.waitFor(() => expect(sdk.run).toHaveBeenCalledOnce());
    await host.requests.operatorAction({
      sessionId: required(started.sessionId),
      action:
        operation === "cancel"
          ? { type: "cancel" }
          : { type: "goal", command: "clear" },
    });
    wait.resolve();
    await idle();
    expect(sdk.run).toHaveBeenCalledOnce();
    expect(host.requests.operatorState().goal?.status).toBe(
      operation === "cancel" ? "active" : "cancelled",
    );
    expect(host.requests.operatorState().goalPaused).toBe(true);
  });
  it("does not complete a goal when stopped during evidence verification", async () => {
    const checking = deferred();
    const wait = deferred();
    const original = goals.createFileGoalHost;
    vi.spyOn(goals, "createFileGoalHost").mockImplementation((options) => {
      const fileHost = original(options);
      return {
        ...fileHost,
        findEvidence: async (goal, ref) => {
          checking.resolve();
          await wait.promise;
          return fileHost.findEvidence(goal, ref);
        },
      };
    });
    sdk.run.mockImplementation((input) =>
      result(input, [
        ...call("execute_command", {}, "verified"),
        ...call("update_goal", {
          status: "complete",
          summary: "Done",
          evidence: [{ tool: "execute_command", quote: "verified" }],
        }),
      ]),
    );
    const started = await host.requests.operatorGoal({ command: "Inspect" });
    await checking.promise;
    await host.requests.operatorAction({
      sessionId: required(started.sessionId),
      action: { type: "cancel" },
    });
    wait.resolve();
    await idle();
    expect(host.requests.operatorState().goal).toMatchObject({
      status: "active",
      completion: null,
    });
    expect(sdk.run).toHaveBeenCalledOnce();
  });
  it("waits for questions and resumes the same goal after the answer", async () => {
    const questions = [
      {
        id: "scope",
        header: "Scope",
        question: "Which environment?",
        options: [{ id: "test", label: "Test" }],
      },
    ];
    sdk.run
      .mockImplementationOnce((input: OffensiveSecurityAgentClientInput) => {
        input.eventBus?.emit("tool-call-complete", {
          toolName: "ask_user_questions",
          toolCallId: "ask_user_questions",
          args: { questions },
        });
        return result(input, call("ask_user_questions", { questions }));
      })
      .mockImplementation((input) => result(input, blocked()));
    const started = await host.requests.operatorGoal({ command: "Inspect" });
    await vi.waitFor(() =>
      expect(host.requests.operatorState().status).toBe("waiting"),
    );
    expect(sdk.run).toHaveBeenCalledOnce();
    expect(host.requests.operatorState().goal?.status).toBe("active");
    await host.requests.operatorAction({
      sessionId: required(started.sessionId),
      action: {
        type: "answer",
        toolCallId: "ask_user_questions",
        skip: false,
        answers: [
          {
            questionId: "scope",
            selectedOptionIds: ["test"],
            freeformText: null,
          },
        ],
      },
    });
    await idle();
    expect(sdk.run).toHaveBeenCalledTimes(2);
    expect(sdk.run.mock.calls[1][0].extraTools.update_goal).toBeDefined();
  });
  it("holds a goal for plan review and continues after approval", async () => {
    sdk.run
      .mockImplementationOnce(
        async (input: OffensiveSecurityAgentClientInput) => {
          await writeFile(
            planFilePath(required(input.session).rootPath),
            "Inspect the fixture",
          );
          input.eventBus?.emit("tool-result", {
            toolName: "submit_plan",
            toolCallId: "plan",
            result: { success: true },
          });
          return result(input, call("submit_plan", {}));
        },
      )
      .mockImplementation((input) => result(input, blocked()));
    const started = await host.requests.operatorGoal({
      command: "Inspect",
      mode: "plan",
    });
    await vi.waitFor(() =>
      expect(host.requests.operatorState().reviewPlan).toBe(true),
    );
    expect(sdk.run).toHaveBeenCalledOnce();
    await host.requests.operatorAction({
      sessionId: required(started.sessionId),
      action: { type: "plan", approve: true },
    });
    await idle();
    expect(sdk.run).toHaveBeenCalledTimes(2);
  });
  it("keeps approvals on the current turn instead of starting a continuation", async () => {
    sdk.run.mockImplementation(
      async (input: OffensiveSecurityAgentClientInput) => {
        await required(input.approvalGate).check("http_request", "request", {
          url: "https://example.test",
        });
        return result(input, blocked());
      },
    );
    const started = await host.requests.operatorGoal({ command: "Inspect" });
    await vi.waitFor(() =>
      expect(host.requests.operatorState().approvals).toHaveLength(1),
    );
    expect(sdk.run).toHaveBeenCalledOnce();
    await host.requests.operatorAction({
      sessionId: required(started.sessionId),
      action: {
        type: "approval",
        id: host.requests.operatorState().approvals[0].id,
        decision: "approve",
      },
    });
    await idle();
    expect(sdk.run).toHaveBeenCalledOnce();
  });
  it("does not start an automatic turn after goals are disabled during the current turn", async () => {
    const wait = deferred();
    sdk.run.mockImplementation(async (input) => {
      await wait.promise;
      return result(input);
    });
    await host.requests.operatorGoal({ command: "Inspect" });
    await vi.waitFor(() => expect(sdk.run).toHaveBeenCalledOnce());
    const cfg = await config.get();
    vi.mocked(config.get).mockResolvedValue({ ...cfg, goalsEnabled: false });
    wait.resolve();
    await idle();
    expect(sdk.run).toHaveBeenCalledOnce();
    expect(host.requests.operatorState()).toMatchObject({
      goalsEnabled: false,
      goalPaused: true,
      goal: { status: "active" },
    });
  });
  it("persists errors as blocked goals without retrying", async () => {
    sdk.run.mockRejectedValue(new Error("Provider unavailable"));
    await host.requests.operatorGoal({ command: "Inspect" });
    await idle();
    expect(host.requests.operatorState().goal).toMatchObject({
      status: "blocked",
      reason: "turn_failed",
      detail: "Provider unavailable",
    });
    expect(sdk.run).toHaveBeenCalledOnce();
  });
  it("restores a stopped goal with an explicit resume control and hides control prompts", async () => {
    sdk.run.mockImplementation((input) => result(input, blocked()));
    const started = await host.requests.operatorGoal({ command: "Inspect" });
    await idle();
    const session = await sessions.get(required(started.sessionId));
    const goal = required(readGoalFile(session.rootPath));
    const { writeGoalFile, continuationMessage } = await import(
      "../../../src/core/goals"
    );
    writeGoalFile(session.rootPath, {
      ...goal,
      status: "active",
      reason: null,
      settledAt: null,
    });
    await writeFile(
      join(session.rootPath, "messages.json"),
      JSON.stringify([
        { role: "user", content: "Goal: Inspect" },
        { role: "user", content: continuationMessage() },
        { role: "assistant", content: "Still inspecting" },
      ]),
    );
    const viewer = createOperatorHost({
      cwd: () => dir,
      requireAcceptance() {},
      emit() {},
    });
    try {
      await viewer.requests.operatorResume({ id: required(started.sessionId) });
      expect(viewer.requests.operatorState().goalPaused).toBe(true);
      expect(
        viewer.requests
          .operatorState()
          .messages.some((m) => isGoalControlMessage(m.content)),
      ).toBe(false);
      expect(sdk.run).toHaveBeenCalledOnce();
      await viewer.requests.operatorAction({
        sessionId: required(started.sessionId),
        action: { type: "resume-goal" },
      });
      await vi.waitFor(() =>
        expect(viewer.requests.operatorState().goal?.status).toBe("blocked"),
      );
      expect(sdk.run).toHaveBeenCalledTimes(2);
    } finally {
      await viewer.close(true);
    }
  });
  it("does not create sessions for status or invalid goals and respects disabled goals and Lance", async () => {
    await host.requests.operatorGoal({ command: "" });
    await host.requests.operatorGoal({ command: "clear" });
    expect(host.sessionId).toBeUndefined();
    await expect(
      host.requests.operatorGoal({ command: "Inspect --rounds 201" }),
    ).rejects.toThrow();
    await expect(
      host.start({ goal: { objective: "Inspect" }, lanceMode: true }),
    ).rejects.toThrow("Lance");
    const cfg = await config.get();
    vi.mocked(config.get).mockResolvedValue({ ...cfg, goalsEnabled: false });
    await expect(
      host.requests.operatorGoal({ command: "Inspect" }),
    ).rejects.toThrow("disabled");
    expect(host.sessionId).toBeUndefined();
    expect(sdk.run).not.toHaveBeenCalled();
  });
  it("discovers project skills before the first message and launches a selected custom skill", async () => {
    await mkdir(join(dir, ".skills", "inspect"), { recursive: true });
    await writeFile(
      join(dir, ".skills", "inspect", "SKILL.md"),
      "---\nname: inspect\ndescription: Inspect local fixtures\n---\nRead the fixture files.",
    );
    const catalog = await host.requests.operatorSkills();
    expect(catalog.some((skill) => skill.slug === "inspect")).toBe(true);
    expect(host.sessionId).toBeUndefined();
    sdk.run.mockImplementation((input) => result(input));
    await host.start({ skill: "inspect", skillArguments: ["login"] });
    await idle();
    expect(sdk.run.mock.calls[0][0].prompt).toContain(
      "Read the fixture files.",
    );
    expect(sdk.run.mock.calls[0][0].prompt).toContain("Operator input: login");
  });
});
