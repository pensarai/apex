import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { writeRecordFiles } from "../../../src/core/agents/offSecAgent/tools/topologyRecords";
import type { OffensiveSecurityAgentClientInput } from "../../../src/core/api";
import { config } from "../../../src/core/config";
import { sessions } from "../../../src/core/session";
import { createOperatorWorkspace } from "./workspace-host";

const sdk = vi.hoisted(() => ({ create: vi.fn() }));
vi.mock("../../../src/core/api", () => ({
  createOffensiveSecurityAgentClient: sdk.create,
}));
vi.mock("../../../src/core/integrations/wandb/upload", () => ({
  attachWandbToEventBus: async () => null,
}));

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("desktop session workspace", () => {
  let dir: string;
  let workspace: ReturnType<typeof createOperatorWorkspace>;
  const emit = vi.fn();
  beforeEach(async () => {
    dir = await mkdtemp(join(os.tmpdir(), "apex-tabs-"));
    vi.spyOn(os, "homedir").mockReturnValue(dir);
    vi.stubEnv("PENSAR_DATA_DIR", join(dir, ".pensar"));
    vi.spyOn(config, "get").mockResolvedValue({
      responsibleUseAccepted: true,
      localModelUrl: "http://127.0.0.1",
      localModelName: "fixture",
      selectedModelId: "fixture",
    });
    sdk.create.mockReset();
    emit.mockReset();
    workspace = createOperatorWorkspace({
      cwd: () => dir,
      requireAcceptance() {},
      emit,
    });
  });
  afterEach(async () => {
    workspace.dispose();
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    await rm(dir, { recursive: true, force: true });
  });
  it("reuses an empty tab across repeated and concurrent new-session requests", async () => {
    const first = await workspace.requests.operatorOpen({});
    const repeated = await Promise.all(
      Array.from({ length: 5 }, () =>
        workspace.requests.operatorOpen({ reuseEmpty: true }),
      ),
    );
    expect(repeated.every((tab) => tab.tabId === first.tabId)).toBe(true);
    expect(await workspace.requests.operatorTabs()).toHaveLength(1);
    await workspace.requests.operatorStart({
      tabId: first.tabId,
      name: "Started",
    });
    const next = await workspace.requests.operatorOpen({ reuseEmpty: true });
    expect(next.tabId).not.toBe(first.tabId);
    expect(
      (await workspace.requests.operatorOpen({ reuseEmpty: true })).tabId,
    ).toBe(next.tabId);
    expect(await workspace.requests.operatorTabs()).toHaveLength(2);
  });
  it("does not reuse an empty tab while it is starting a session", async () => {
    const first = await workspace.requests.operatorOpen({});
    const starting = workspace.requests.operatorStart({
      tabId: first.tabId,
      name: "Starting",
    });
    const next = await workspace.requests.operatorOpen({ reuseEmpty: true });
    expect(next.tabId).not.toBe(first.tabId);
    await starting;
  });
  it("keeps attack surfaces isolated between session tabs", async () => {
    const first = await workspace.requests.operatorOpen({});
    const second = await workspace.requests.operatorOpen({});
    const one = await workspace.requests.operatorStart({
      tabId: first.tabId,
      name: "One",
    });
    const two = await workspace.requests.operatorStart({
      tabId: second.tabId,
      name: "Two",
    });
    const session = await sessions.get(one.sessionId);
    writeRecordFiles(session.rootPath, [
      {
        kind: "boundary",
        file: "boundary_one.json",
        record: { id: "bnd_one", name: "First session only" },
      },
    ]);
    expect(
      workspace.requests.operatorAttackSurface({
        tabId: first.tabId,
        sessionId: one.sessionId,
      }).boundaries,
    ).toHaveLength(1);
    expect(
      workspace.requests.operatorAttackSurface({
        tabId: second.tabId,
        sessionId: two.sessionId,
      }).boundaries,
    ).toHaveLength(0);
    expect(() =>
      workspace.requests.operatorAttackSurface({
        tabId: second.tabId,
        sessionId: one.sessionId,
      }),
    ).toThrow("active session changed");
    await workspace.requests.operatorClose({ tabId: first.tabId });
    expect(() =>
      workspace.requests.operatorAttackSurface({
        tabId: first.tabId,
        sessionId: one.sessionId,
      }),
    ).toThrow("no longer open");
  });
  it("keeps simultaneous streams, approvals, queues, and cancellation isolated", async () => {
    const clients: {
      input?: OffensiveSecurityAgentClientInput;
      abort: ReturnType<typeof vi.fn>;
      done: ReturnType<typeof deferred>;
    }[] = [];
    sdk.create.mockImplementation(() => {
      const done = deferred();
      const client = {
        input: undefined as OffensiveSecurityAgentClientInput | undefined,
        abort: vi.fn(done.resolve),
        done,
      };
      clients.push(client);
      return {
        abort: client.abort,
        async run(input: OffensiveSecurityAgentClientInput) {
          client.input = input;
          await done.promise;
          return {
            session: input.session,
            streamResult: { response: { messages: [] } },
          };
        },
      };
    });
    const first = await workspace.requests.operatorOpen({});
    const second = await workspace.requests.operatorOpen({});
    const one = await workspace.requests.operatorStart({
      tabId: first.tabId,
      name: "First",
      prompt: "One",
    });
    const two = await workspace.requests.operatorStart({
      tabId: second.tabId,
      name: "Second",
      prompt: "Two",
    });
    await vi.waitFor(() =>
      expect(clients.every((client) => client.input)).toBe(true),
    );
    workspace.requests.operatorWatch({ tabId: first.tabId, key: "first" });
    workspace.requests.operatorWatch({ tabId: second.tabId, key: "second" });
    const state = (tabId: string) =>
      workspace.requests.operatorState({ tabId });
    clients[0].input?.eventBus?.emit("text-delta", { text: "First response" });
    clients[1].input?.eventBus?.emit("text-delta", { text: "Second response" });
    await workspace.requests.operatorAction({
      tabId: first.tabId,
      sessionId: one.sessionId,
      action: { type: "send", text: "Follow up" },
    });
    const approval = clients[0].input?.approvalGate
      ?.check("http_request", "tool", {})
      .then(
        () => true,
        () => false,
      );
    expect(state(first.tabId).approvals).toHaveLength(1);
    expect(state(second.tabId).approvals).toHaveLength(0);
    expect(state(first.tabId).queue).toHaveLength(1);
    expect(state(second.tabId).queue).toHaveLength(0);
    await vi.waitFor(() =>
      expect(
        emit.mock.calls.some(([event]) => event.tabId === first.tabId),
      ).toBe(true),
    );
    expect(
      emit.mock.calls.some(([event]) => event.tabId === second.tabId),
    ).toBe(true);
    expect(state(first.tabId).messages.map((m) => m.content)).not.toContain(
      "Second response",
    );
    await expect(
      workspace.requests.operatorClose({ tabId: first.tabId }),
    ).rejects.toThrow("active");
    await workspace.requests.operatorClose({ tabId: first.tabId, stop: true });
    expect(await approval).toBe(false);
    expect(clients[0].abort).toHaveBeenCalled();
    expect(clients[1].abort).not.toHaveBeenCalled();
    expect(workspace.hasSession(one.sessionId)).toBe(false);
    expect(workspace.hasSession(two.sessionId)).toBe(true);
    expect(state(second.tabId).status).toBe("running");
    await workspace.requests.operatorClose({ tabId: second.tabId, stop: true });
    expect(sdk.create).toHaveBeenCalledTimes(2);
  });
  it("opens a saved session once even when resume requests race, and reopens after closing", async () => {
    const snapshot = await workspace.start({ name: "Saved" });
    const original = await workspace.requests.operatorOpen({
      sessionId: snapshot.sessionId,
    });
    expect(await workspace.requests.operatorTabs()).toHaveLength(1);
    await workspace.requests.operatorClose({ tabId: original.tabId });
    await workspace.requests.operatorClose({ tabId: original.tabId });
    const get = vi.spyOn(sessions, "get");
    const [first, second] = await Promise.all([
      workspace.requests.operatorOpen({ sessionId: snapshot.sessionId }),
      workspace.requests.operatorOpen({ sessionId: snapshot.sessionId }),
    ]);
    expect(first.tabId).toBe(second.tabId);
    expect(first.tabId).not.toBe(original.tabId);
    expect(get).toHaveBeenCalledOnce();
    expect(await workspace.requests.operatorTabs()).toHaveLength(1);
    const blank = await workspace.requests.operatorOpen({});
    await expect(
      workspace.requests.operatorResume({
        tabId: blank.tabId,
        id: snapshot.sessionId,
      }),
    ).rejects.toThrow("another tab");
    await expect(
      workspace.requests.operatorStart({
        tabId: first.tabId,
        name: "Replacement",
      }),
    ).rejects.toThrow("new tab");
    expect(
      workspace.requests.operatorState({ tabId: first.tabId }).sessionId,
    ).toBe(snapshot.sessionId);
  });
  it("waits for an in-flight launch and abort cleanup before releasing a closing tab", async () => {
    const launch = deferred();
    const drained = deferred();
    const aborted = deferred();
    const originalGet = config.get;
    vi.mocked(config.get).mockImplementationOnce(async () => {
      await launch.promise;
      return originalGet();
    });
    sdk.create.mockReturnValue({
      abort: aborted.resolve,
      async run(input: OffensiveSecurityAgentClientInput) {
        await aborted.promise;
        await drained.promise;
        return {
          session: input.session,
          streamResult: { response: { messages: [] } },
        };
      },
    });
    const tab = await workspace.requests.operatorOpen({});
    const starting = workspace.requests.operatorStart({
      tabId: tab.tabId,
      prompt: "Run",
    });
    let closed = false;
    const closing = workspace.requests
      .operatorClose({ tabId: tab.tabId, stop: true })
      .then(() => {
        closed = true;
      });
    expect(() =>
      workspace.requests.operatorAction({
        tabId: tab.tabId,
        sessionId: "unknown",
        action: { type: "send", text: "Late" },
      }),
    ).toThrow("closing");
    launch.resolve();
    const snapshot = await starting;
    await aborted.promise;
    expect(closed).toBe(false);
    expect(workspace.hasSession(snapshot.sessionId)).toBe(true);
    drained.resolve();
    await closing;
    expect(workspace.hasSession(snapshot.sessionId)).toBe(false);
    expect(await workspace.requests.operatorTabs()).toHaveLength(0);
  });
  it("retains each tab’s directory and reports the saved directory on resume", async () => {
    const other = join(dir, "other");
    await mkdir(other);
    const first = await workspace.requests.operatorOpen({});
    const second = await workspace.requests.operatorOpen({});
    await workspace.requests.operatorSetDirectory({
      tabId: first.tabId,
      cwd: other,
    });
    const started = await workspace.requests.operatorStart({
      tabId: first.tabId,
      name: "Scoped",
    });
    expect(
      (await workspace.requests.operatorTabs()).find(
        (tab) => tab.tabId === second.tabId,
      )?.cwd,
    ).toBe(dir);
    await expect(
      workspace.requests.operatorSetDirectory({ tabId: first.tabId, cwd: dir }),
    ).rejects.toThrow("new session");
    await workspace.requests.operatorClose({ tabId: first.tabId });
    expect(
      (await workspace.requests.operatorOpen({ sessionId: started.sessionId }))
        .cwd,
    ).toBe(await realpath(other));
    await writeFile(join(dir, "file"), "fixture");
    await expect(
      workspace.requests.operatorSetDirectory({
        tabId: second.tabId,
        cwd: join(dir, "file"),
      }),
    ).rejects.toThrow("directory");
  });
  it("waits for a pending launch when the view reloads its open tabs", async () => {
    const pending = deferred();
    const get = config.get;
    vi.mocked(config.get).mockImplementationOnce(async () => {
      await pending.promise;
      return get();
    });
    const starting = workspace.start({ name: "Opening" });
    const listing = workspace.requests.operatorTabs();
    pending.resolve();
    const session = await starting;
    const tabs = await listing;
    expect(tabs).toHaveLength(1);
    expect(tabs[0].snapshot.sessionId).toBe(session.sessionId);
  });
  it.each([
    "configuration",
    "creation",
  ] as const)("does not start an SDK client after disposal during %s", async (stage) => {
    const blocked = deferred();
    const entered = deferred();
    const create = sessions.create.bind(sessions);
    const createSpy = vi.spyOn(sessions, "create");
    if (stage === "configuration") {
      const get = config.get;
      vi.mocked(config.get).mockImplementationOnce(async () => {
        entered.resolve();
        await blocked.promise;
        return get();
      });
    } else {
      createSpy.mockImplementationOnce(async (...args) => {
        const session = await create(...args);
        entered.resolve();
        await blocked.promise;
        return session;
      });
    }
    const starting = workspace.start({ prompt: "Run" });
    await entered.promise;
    workspace.dispose();
    blocked.resolve();
    await expect(starting).rejects.toThrow("closed");
    expect(sdk.create).not.toHaveBeenCalled();
    if (stage === "configuration") expect(createSpy).not.toHaveBeenCalled();
  });
  it("releases ownership when a corrupt transcript fails after assigning its session", async () => {
    const saved = await workspace.start({ name: "Corrupt" });
    const tab = await workspace.requests.operatorOpen({
      sessionId: saved.sessionId,
    });
    await workspace.requests.operatorClose({ tabId: tab.tabId });
    vi.spyOn(sessions, "hasOperatorState").mockReturnValue(true);
    vi.spyOn(sessions, "loadOperatorState").mockResolvedValue(null);
    await expect(
      workspace.requests.operatorOpen({ sessionId: saved.sessionId }),
    ).rejects.toThrow("saved operator transcript");
    expect(workspace.hasSession(saved.sessionId)).toBe(false);
    expect(await workspace.requests.operatorTabs()).toHaveLength(0);
  });
  it("releases failed opens and rejects operations after disposal", async () => {
    await expect(
      workspace.requests.operatorOpen({ sessionId: "../invalid" }),
    ).rejects.toThrow("Invalid session ID");
    expect(await workspace.requests.operatorTabs()).toHaveLength(0);
    await expect(workspace.start({ model: "unavailable" })).rejects.toThrow(
      "unavailable",
    );
    expect(await workspace.requests.operatorTabs()).toHaveLength(0);
    workspace.dispose();
    expect(() => workspace.requests.operatorOpen({})).toThrow("closed");
  });
});
