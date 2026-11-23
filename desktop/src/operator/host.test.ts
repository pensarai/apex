import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { writeRecordFiles } from "../../../src/core/agents/offSecAgent/tools/topologyRecords";
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
  it("reads the session attack surface from persisted records, including updates and retirements", async () => {
    const { sessionId } = await host.start({ name: "Recon" });
    const session = await sessions.get(sessionId);
    expect(host.requests.operatorAttackSurface({ sessionId })).toEqual({
      boundaries: [],
      components: [],
      flows: [],
      controls: [],
      threats: [],
      retired: [],
    });
    writeRecordFiles(session.rootPath, [
      {
        kind: "boundary",
        file: "boundary_1.json",
        record: {
          id: "bnd_root",
          name: "Production",
          recordedAt: "2026-11-01T00:00:00Z",
        },
      },
      {
        kind: "component",
        file: "component_1.json",
        record: {
          id: "cmp_api",
          name: "API",
          boundaryId: "bnd_root",
          recordedAt: "2026-11-01T00:00:00Z",
        },
      },
      {
        kind: "flow",
        file: "flow_1.json",
        record: {
          id: "flw_one",
          fromId: "cmp_api",
          to: "External service",
          label: "HTTPS",
          recordedAt: "2026-11-01T00:00:00Z",
        },
      },
    ]);
    expect(
      host.requests.operatorAttackSurface({ sessionId }).components[0],
    ).toMatchObject({ name: "API", boundary: "Production" });
    writeRecordFiles(session.rootPath, [
      {
        kind: "component",
        file: "component_2.json",
        record: {
          id: "cmp_api",
          name: "Public API",
          boundaryId: "bnd_root",
          recordedAt: "2026-11-02T00:00:00Z",
        },
      },
      {
        kind: "boundary",
        file: "boundary_2.json",
        record: {
          id: "bnd_root",
          name: "Production",
          status: "retired",
          recordedAt: "2026-11-02T00:00:00Z",
        },
      },
    ]);
    const topology = host.requests.operatorAttackSurface({ sessionId });
    expect(topology.components).toHaveLength(1);
    expect(topology.flows[0].from).toBe("Public API");
    expect(topology.boundaries).toEqual([]);
    expect(topology.retired[0]).toMatchObject({
      kind: "boundary",
      record: { id: "bnd_root" },
    });
    expect(() =>
      host.requests.operatorAttackSurface({ sessionId: "another-session" }),
    ).toThrow("active session changed");
    host.dispose();
    host = createOperatorHost({
      cwd: () => dir,
      requireAcceptance() {},
      emit() {},
    });
    await host.resume({ id: sessionId });
    expect(host.requests.operatorAttackSurface({ sessionId })).toEqual(
      topology,
    );
  });
  it("reports inline activity from root events and clears it after completion", async () => {
    let finish!: () => void;
    const pending = new Promise<void>((resolve) => {
      finish = resolve;
    });
    let input!: OffensiveSecurityAgentClientInput;
    sdk.run.mockImplementation(
      async (value: OffensiveSecurityAgentClientInput) => {
        input = value;
        await pending;
        return {
          session: value.session,
          streamResult: { response: Promise.resolve({ messages: [] }) },
        };
      },
    );
    await host.start({ name: "Activity", prompt: "Hello" });
    await vi.waitFor(() => expect(sdk.run).toHaveBeenCalledOnce());
    const activity = () => host.requests.operatorState().activity;
    try {
      const bus = input.eventBus;
      const gate = input.approvalGate;
      if (!bus || !gate) throw new Error("Missing operator wiring");
      expect(activity()).toBe("waiting");
      bus.emit("reasoning-start", { subagentId: "worker" });
      expect(activity()).toBe("waiting");
      bus.emit("reasoning-start", {});
      expect(activity()).toBe("thinking");
      bus.emit("reasoning-delta", {
        text: "Inspect the authentication boundary.",
      });
      expect(activity()).toBe("thinking");
      expect(JSON.stringify(host.requests.operatorState())).toContain(
        "Inspect the authentication boundary.",
      );
      bus.emit("reasoning-end", {});
      expect(activity()).toBe("waiting");
      bus.emit("text-delta", { text: "Checking." });
      expect(activity()).toBe("responding");
      for (const toolCallId of ["one", "two"]) {
        bus.emit("tool-call-start", { toolCallId, toolName: "http_request" });
        bus.emit("tool-call-complete", {
          toolCallId,
          toolName: "http_request",
          args: {},
        });
      }
      expect(activity()).toBe("working");
      bus.emit("tool-result", {
        toolCallId: "one",
        toolName: "http_request",
        result: "Done",
      });
      expect(activity()).toBe("working");
      bus.emit("tool-result", {
        toolCallId: "two",
        toolName: "http_request",
        result: "Done",
      });
      expect(activity()).toBe("waiting");
      const approval = gate.check("http_request", "approval", {});
      try {
        expect(activity()).toBeUndefined();
      } finally {
        for (const pending of gate.getPendingApprovals())
          gate.approve(pending.id);
        await approval;
      }
      expect(activity()).toBe("waiting");
    } finally {
      finish();
      await vi.waitFor(() =>
        expect(host.requests.operatorState().status).toBe("idle"),
      );
    }
    expect(activity()).toBeUndefined();
    input.eventBus?.emit("reasoning-start", {});
    expect(activity()).toBeUndefined();
  });
  it("streams background processes in snapshots and cancels only a current job", async () => {
    let finish!: () => void;
    const pending = new Promise<void>((resolve) => {
      finish = resolve;
    });
    let input!: OffensiveSecurityAgentClientInput;
    const cancel = vi.fn(async (jobId: string) => {
      input.eventBus?.emit("background-job", {
        jobId,
        command: "sleep 30",
        startedAt: 1,
        status: "completed",
        stdout: "partial",
        stderr: "aborted",
        exitCode: 130,
        finishedAt: 2,
      });
    });
    sdk.run.mockImplementation(
      async (value: OffensiveSecurityAgentClientInput) => {
        input = value;
        if (value.commandCancelHandle)
          value.commandCancelHandle.cancelBackground = cancel;
        await pending;
        return {
          session: value.session,
          streamResult: { response: Promise.resolve({ messages: [] }) },
        };
      },
    );
    const { sessionId } = await host.start({
      name: "Process sidebar",
      prompt: "Start jobs",
    });
    await vi.waitFor(() => expect(sdk.run).toHaveBeenCalledOnce());
    const job = {
      jobId: "job-1",
      command: "sleep 30",
      startedAt: 1,
      status: "running" as const,
      stdout: "",
      stderr: "",
    };
    try {
      input.eventBus?.emit("background-job", job);
      input.eventBus?.emit("background-job", { ...job, stdout: "partial" });
      input.eventBus?.emit("background-job", { ...job, jobId: "job-2" });
      input.eventBus?.emit("step-finish", { messages: [] });
      expect(host.requests.operatorState().activity).toBe("working");
      expect(host.requests.operatorState().processes).toHaveLength(2);
      expect(host.requests.operatorState().processes?.[0].stdout).toBe(
        "partial",
      );
      await host.requests.operatorAction({
        sessionId,
        action: { type: "cancel-process", jobId: "job-1" },
      });
      expect(cancel).toHaveBeenCalledOnce();
      expect(cancel).toHaveBeenCalledWith("job-1");
      expect(sdk.abort).not.toHaveBeenCalled();
      expect(
        host.requests.operatorState().processes?.map((p) => p.status),
      ).toEqual(["completed", "running"]);
      await expect(
        host.requests.operatorAction({
          sessionId,
          action: { type: "cancel-process", jobId: "job-1" },
        }),
      ).rejects.toThrow("no longer available");
      await expect(
        host.requests.operatorAction({
          sessionId,
          action: { type: "cancel-process", jobId: "other-job" },
        }),
      ).rejects.toThrow("no longer available");
    } finally {
      finish();
      await vi.waitFor(() =>
        expect(host.requests.operatorState().status).toBe("idle"),
      );
    }
    input.eventBus?.emit("background-job", { ...job, jobId: "late" });
    expect(host.requests.operatorState().processes).toHaveLength(2);
    await host.start({ name: "Another session" });
    expect(host.requests.operatorState().processes).toEqual([]);
  });

  it("cancels only the command named by the clicked row, rejecting stale rows", async () => {
    let finish!: () => void;
    const pending = new Promise<void>((resolve) => {
      finish = resolve;
    });
    let input!: OffensiveSecurityAgentClientInput;
    const cancel = vi.fn(() => true);
    sdk.run.mockImplementation(
      async (value: OffensiveSecurityAgentClientInput) => {
        input = value;
        if (value.commandCancelHandle)
          value.commandCancelHandle.cancel = cancel;
        await pending;
        return {
          session: value.session,
          streamResult: { response: Promise.resolve({ messages: [] }) },
        };
      },
    );
    const { sessionId } = await host.start({
      name: "Cancel command",
      prompt: "Run a command",
    });
    await vi.waitFor(() => expect(sdk.run).toHaveBeenCalledOnce());
    const start = (toolCallId: string) =>
      input.eventBus?.emit("tool-call-complete", {
        toolCallId,
        toolName: "execute_command",
        args: { command: "sleep 30" },
      });
    const cancelRow = (toolCallId: string) =>
      host.requests.operatorAction({
        sessionId,
        action: { type: "cancel-command", toolCallId },
      });
    try {
      start("first");
      await cancelRow("first");
      expect(cancel).toHaveBeenCalledOnce();
      input.eventBus?.emit("tool-result", {
        toolCallId: "first",
        toolName: "execute_command",
        result: "Cancelled",
      });
      start("second");
      await expect(cancelRow("first")).rejects.toThrow("no longer running");
      expect(cancel).toHaveBeenCalledOnce();
      await cancelRow("second");
      expect(cancel).toHaveBeenCalledTimes(2);
      expect(sdk.abort).not.toHaveBeenCalled();
    } finally {
      finish();
      await vi.waitFor(() =>
        expect(host.requests.operatorState().status).toBe("idle"),
      );
    }
  });
  it("applies a selected model to the next turn while preserving the running turn's model", async () => {
    let finish!: () => void;
    const pending = new Promise<void>((resolve) => {
      finish = resolve;
    });
    sdk.run.mockImplementation(
      async (value: OffensiveSecurityAgentClientInput) => {
        await pending;
        return {
          session: value.session,
          streamResult: { response: Promise.resolve({ messages: [] }) },
        };
      },
    );
    const { sessionId } = await host.start({
      name: "Model switch",
      model: "fixture",
      prompt: "First turn",
    });
    await vi.waitFor(() => expect(sdk.run).toHaveBeenCalledOnce());
    try {
      vi.mocked(config.get).mockResolvedValue({
        responsibleUseAccepted: true,
        localModelUrl: "http://127.0.0.1",
        localModelName: "next-model",
        selectedModelId: "next-model",
      });
      const selected = await host.requests.operatorAction({
        sessionId,
        action: { type: "model", id: "next-model" },
      });
      expect(selected.model).toBe("fixture");
      expect(selected.status).toBe("running");
      await expect(
        host.requests.operatorAction({
          sessionId,
          action: { type: "model", id: "unavailable" },
        }),
      ).rejects.toThrow("unavailable");
    } finally {
      finish();
      await vi.waitFor(() =>
        expect(host.requests.operatorState().status).toBe("idle"),
      );
    }
    await host.requests.operatorAction({
      sessionId,
      action: { type: "send", text: "Next turn" },
    });
    await vi.waitFor(() => expect(sdk.run).toHaveBeenCalledTimes(2));
    expect(sdk.run.mock.calls[1][0].model).toBe("next-model");
    await vi.waitFor(() =>
      expect(host.requests.operatorState().status).toBe("idle"),
    );
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
          eventBus.emit("reasoning-start", { subagentId: "worker" });
          eventBus.emit("reasoning-delta", {
            subagentId: "worker",
            text: "Inspect the worker scope.",
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
    expect(
      host.requests.operatorState().subagents[0]?.messages[0]?.reasoning,
    ).toMatchObject({ text: "Inspect the worker scope.", complete: true });
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
    expect(host.requests.operatorState().activity).toBeUndefined();
    expect(host.requests.operatorState().error).toBeUndefined();
    expect(sdk.run).toHaveBeenCalledTimes(1);
  });
  it("carries child spawn identity and loading through snapshots and stream frames", async () => {
    const emit = vi.fn();
    const viewer = createOperatorHost({
      cwd: () => dir,
      requireAcceptance() {},
      emit,
    });
    let finish = () => {};
    const wait = new Promise<void>((resolve) => {
      finish = resolve;
    });
    sdk.run.mockImplementation(
      async (input: OffensiveSecurityAgentClientInput) => {
        input.eventBus?.emit("subagent-spawn", {
          subagentId: "child",
          name: "API recon",
          input: { goal: "Map API" },
          parentToolCallId: "call-recon",
        });
        input.eventBus?.emit("model-loading", {
          subagentId: "child",
          model: "fixture",
          status: "loading",
          elapsedMs: 0,
        });
        await wait;
        input.eventBus?.emit("subagent-complete", {
          subagentId: "child",
          status: "completed",
        });
        return {
          session: input.session,
          streamResult: { response: { messages: [] } },
        };
      },
    );
    try {
      const { sessionId } = await viewer.start({ name: "Recon" });
      viewer.requests.operatorWatch({ key: "view" });
      await viewer.requests.operatorAction({
        sessionId,
        action: { type: "send", text: "Inspect" },
      });
      await vi.waitFor(() =>
        expect(viewer.requests.operatorState().subagents).toHaveLength(1),
      );
      const expected = {
        id: "child",
        name: "API recon",
        parentToolCallId: "call-recon",
        input: { goal: "Map API" },
        modelLoading: "fixture",
        spawnedAt: expect.any(String),
      };
      expect(viewer.requests.operatorState().subagents[0]).toMatchObject(
        expected,
      );
      await vi.waitFor(() =>
        expect(emit.mock.lastCall?.[0].subagents[0]).toMatchObject(expected),
      );
      finish();
      await vi.waitFor(() =>
        expect(viewer.requests.operatorState().status).toBe("idle"),
      );
      expect(viewer.requests.operatorState().subagents[0]).toMatchObject({
        status: "completed",
        completedAt: expect.any(String),
      });
      expect(
        viewer.requests.operatorState().subagents[0].modelLoading,
      ).toBeUndefined();
    } finally {
      finish();
      viewer.dispose();
    }
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
