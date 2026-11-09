import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { OffensiveSecurityAgentClientInput } from "../../../src/core/api";
import { config } from "../../../src/core/config";
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

describe("desktop operator", () => {
  let dir: string;
  let host: ReturnType<typeof createOperatorHost>;
  beforeEach(async () => {
    dir = await mkdtemp(join(os.tmpdir(), "apex-operator-"));
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
    host.dispose();
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    await rm(dir, { recursive: true, force: true });
  });
  it("checks resume IDs and unavailable models before creating or loading a session", async () => {
    await expect(
      host.requests.operatorResume({ id: "../keys" }),
    ).rejects.toThrow("Invalid session ID");
    await expect(
      host.start({ model: "missing", name: "invalid" }),
    ).rejects.toThrow("unavailable");
    expect(host.requests.operatorState().sessionId).toBeUndefined();
  });
  it("holds manual tool execution, follows subagents, accepts subsequent turns, and resumes their transcript", async () => {
    sdk.run.mockImplementation(
      async (input: OffensiveSecurityAgentClientInput) => {
        const { session, eventBus, approvalGate } = input;
        if (!session || !eventBus || !approvalGate)
          throw new Error("Missing operator wiring");
        if (input.prompt === "check") {
          eventBus.emit("subagent-spawn", {
            subagentId: "worker",
            name: "Worker",
            input: { target: "fixture" },
          });
          eventBus.emit("text-delta", {
            subagentId: "worker",
            text: "Worker result",
          });
          eventBus.emit("subagent-complete", {
            subagentId: "worker",
            status: "completed",
          });
          await approvalGate.check("http_request", "tc-1", {
            url: "https://fixture.invalid",
          });
        }
        eventBus.emit("text-delta", { text: "Done." });
        await writeFile(
          join(session.rootPath, "messages.json"),
          JSON.stringify([
            ...(input.messages ?? []),
            { role: "assistant", content: "Done." },
          ]),
        );
        return { session, streamResult: { response: { messages: [] } } };
      },
    );
    const { sessionId } = await host.start({
      name: "Fixture",
      target: "https://fixture.invalid",
      prompt: "check",
    });
    await vi.waitFor(() =>
      expect(host.requests.operatorState().approvals).toHaveLength(1),
    );
    const approval = host.requests.operatorState().approvals[0];
    await expect(host.start({ name: "second" })).rejects.toThrow(
      "current operator",
    );
    await host.requests.operatorAction({
      sessionId,
      action: { type: "approval", id: approval.id, decision: "approve" },
    });
    await vi.waitFor(() =>
      expect(host.requests.operatorState().status).toBe("idle"),
    );
    expect(
      host.requests.operatorState().subagents[0]?.messages[0]?.content,
    ).toContain("Worker result");
    await host.requests.operatorAction({
      sessionId,
      action: { type: "send", text: "follow up" },
    });
    await vi.waitFor(() => expect(sdk.run).toHaveBeenCalledTimes(2));
    await vi.waitFor(() =>
      expect(host.requests.operatorState().status).toBe("idle"),
    );
    expect(sdk.run.mock.lastCall?.[0].messages).toEqual([
      { role: "user", content: "check" },
      { role: "assistant", content: "Done." },
      { role: "user", content: "follow up" },
    ]);
    const restored = createOperatorHost({
      cwd: () => dir,
      requireAcceptance() {},
      emit() {},
    });
    try {
      const snapshot = await restored.requests.operatorResume({
        id: sessionId,
      });
      expect(snapshot.messages.map((m) => m.content)).toEqual([
        "check",
        "Done.",
        "follow up",
        "Done.",
      ]);
    } finally {
      restored.dispose();
    }
  });
  it("uses the same credential reference across turns and a fresh host without exposing the secret to the view", async () => {
    const seen: string[] = [];
    sdk.run.mockImplementation(
      async (input: OffensiveSecurityAgentClientInput) => {
        const manager = input.session?.credentialManager;
        const [ref] = manager?.listReferences() ?? [];
        if (!input.session || !ref || !manager)
          throw new Error("Missing credential");
        expect(manager.resolve(ref.id)?.password).toBe("secret-fixture");
        seen.push(ref.id);
        await writeFile(
          join(input.session.rootPath, "messages.json"),
          JSON.stringify(input.messages),
        );
        return {
          session: input.session,
          streamResult: { response: { messages: [] } },
        };
      },
    );
    const first = await host.start({
      name: "Credential fixture",
      authCredentials: [
        { username: "fixture", password: "secret-fixture", role: "tester" },
      ],
      prompt: "Inspect",
    });
    await vi.waitFor(() =>
      expect(host.requests.operatorState().status).toBe("idle"),
    );
    expect(JSON.stringify(host.requests.operatorState())).not.toContain(
      "secret-fixture",
    );
    const restored = createOperatorHost({
      cwd: () => dir,
      requireAcceptance() {},
      emit() {},
    });
    try {
      await restored.requests.operatorResume({ id: first.sessionId });
      await restored.requests.operatorAction({
        sessionId: first.sessionId,
        action: { type: "send", text: "Continue" },
      });
      await vi.waitFor(() =>
        expect(restored.requests.operatorState().status).toBe("idle"),
      );
      expect(seen).toHaveLength(2);
      expect(seen[1]).toBe(seen[0]);
      expect(JSON.stringify(restored.requests.operatorState())).not.toContain(
        "secret-fixture",
      );
    } finally {
      restored.dispose();
    }
  });
  it("drains running work before restart and drops queued messages on cancellation", async () => {
    let release: () => void = () => {};
    const pending = new Promise<void>((r) => {
      release = r;
    });
    sdk.abort.mockImplementation(release);
    sdk.run.mockImplementation(
      async (input: OffensiveSecurityAgentClientInput) => {
        input.eventBus?.emit("text-delta", { text: "Checking…" });
        await pending;
        throw new Error("Aborted");
      },
    );
    const { sessionId } = await host.start({ name: "Cancel", prompt: "Run" });
    await vi.waitFor(() => expect(sdk.run).toHaveBeenCalledTimes(1));
    await host.requests.operatorAction({
      sessionId,
      action: { type: "send", text: "Next" },
    });
    expect(host.requests.operatorState().queue).toHaveLength(1);
    await host.requests.operatorAction({
      sessionId,
      action: { type: "cancel" },
    });
    await vi.waitFor(() =>
      expect(host.requests.operatorState().status).toBe("idle"),
    );
    expect(host.requests.operatorState().queue).toHaveLength(0);
    expect(host.requests.operatorState().error).toBeUndefined();
    expect(sdk.run).toHaveBeenCalledTimes(1);
  });
  it("streams only changed transcript suffixes while subscribed and catches up after reattachment", async () => {
    const emit = vi.fn();
    const viewer = createOperatorHost({
      cwd: () => dir,
      requireAcceptance() {},
      emit,
    });
    let release: () => void = () => {};
    const releaseTurn = new Promise<void>((r) => {
      release = r;
    });
    sdk.run.mockImplementation(
      async (input: OffensiveSecurityAgentClientInput) => {
        input.eventBus?.emit("text-delta", { text: "One" });
        await releaseTurn;
        input.eventBus?.emit("text-delta", { text: " two" });
        return {
          session: input.session,
          streamResult: { response: { messages: [] } },
        };
      },
    );
    try {
      const { sessionId } = await viewer.start({ name: "Stream" });
      const initial = viewer.requests.operatorWatch({ key: "first" });
      await viewer.requests.operatorAction({
        sessionId,
        action: { type: "send", text: "Inspect" },
      });
      await vi.waitFor(() => expect(emit).toHaveBeenCalled());
      const frame = emit.mock.lastCall?.[0];
      expect(frame.baseRevision).toBe(initial.revision);
      expect(
        frame.transcript.messages.map((m: { content: string }) => m.content),
      ).toEqual(["Inspect", "One"]);
      viewer.requests.operatorUnwatch({ key: "first" });
      const count = emit.mock.calls.length;
      release();
      await vi.waitFor(() =>
        expect(viewer.requests.operatorState().status).toBe("idle"),
      );
      expect(emit).toHaveBeenCalledTimes(count);
      expect(
        viewer.requests.operatorWatch({ key: "next" }).messages.at(-1)?.content,
      ).toBe("One two");
    } finally {
      release();
      viewer.dispose();
    }
  });
  it("requires plan review before execution and uses manual approvals for an accepted plan", async () => {
    sdk.run.mockImplementation(
      async (input: OffensiveSecurityAgentClientInput) => {
        if (!input.session) throw new Error("Missing session");
        if (input.mode === "plan") {
          await writeFile(
            planFilePath(input.session.rootPath),
            "Inspect the fixture.",
          );
          input.eventBus?.emit("tool-result", {
            toolName: "submit_plan",
            toolCallId: "plan",
            result: { success: true },
          });
        }
        await writeFile(
          join(input.session.rootPath, "messages.json"),
          JSON.stringify(input.messages),
        );
        return {
          session: input.session,
          streamResult: { response: { messages: [] } },
        };
      },
    );
    const { sessionId } = await host.start({
      name: "Plan",
      mode: "plan",
      prompt: "Plan research",
    });
    await vi.waitFor(() =>
      expect(host.requests.operatorState().status).toBe("waiting"),
    );
    expect(host.requests.operatorState().plan).toBe("Inspect the fixture.");
    await host.requests.operatorAction({
      sessionId,
      action: { type: "plan", approve: true },
    });
    await vi.waitFor(() => expect(sdk.run).toHaveBeenCalledTimes(2));
    await vi.waitFor(() =>
      expect(host.requests.operatorState().status).toBe("idle"),
    );
    expect(host.requests.operatorState().mode).toBe("manual");
    expect(
      (await sessions.get(sessionId)).config?.operatorSettings?.initialMode,
    ).toBe("manual");
    expect(sdk.run.mock.lastCall?.[0].system).toContain("Inspect the fixture.");
  });
  it("patches the question tool result before continuing", async () => {
    sdk.run.mockImplementation(
      async (input: OffensiveSecurityAgentClientInput) => {
        if (!input.session) throw new Error("Missing session");
        const messages = [...(input.messages ?? [])];
        if (input.prompt) {
          const questions = [
            {
              id: "env",
              header: "Environment",
              question: "Which environment?",
              options: [{ id: "local", label: "Local" }],
            },
          ];
          input.eventBus?.emit("tool-call-complete", {
            toolName: "ask_user_questions",
            toolCallId: "question",
            args: { questions },
          });
          messages.push(
            {
              role: "assistant",
              content: [
                {
                  type: "tool-call",
                  toolCallId: "question",
                  toolName: "ask_user_questions",
                  input: { questions },
                },
              ],
            },
            {
              role: "tool",
              content: [
                {
                  type: "tool-result",
                  toolCallId: "question",
                  toolName: "ask_user_questions",
                  output: { type: "json", value: { pendingQuestionCount: 1 } },
                },
              ],
            },
          );
        }
        await writeFile(
          join(input.session.rootPath, "messages.json"),
          JSON.stringify(messages),
        );
        return {
          session: input.session,
          streamResult: { response: { messages: [] } },
        };
      },
    );
    const { sessionId } = await host.start({
      name: "Questions",
      prompt: "Inspect",
    });
    await vi.waitFor(() =>
      expect(host.requests.operatorState().status).toBe("waiting"),
    );
    const answers = [
      { questionId: "env", selectedOptionIds: ["local"], freeformText: null },
    ];
    await host.requests.operatorAction({
      sessionId,
      action: { type: "answer", toolCallId: "question", skip: false, answers },
    });
    await vi.waitFor(() => expect(sdk.run).toHaveBeenCalledTimes(2));
    await vi.waitFor(() =>
      expect(host.requests.operatorState().status).toBe("idle"),
    );
    expect(
      sdk.run.mock.lastCall?.[0].messages.at(-1).content[0].output,
    ).toEqual({ type: "json", value: { answers, skipped: false } });
  });
});
