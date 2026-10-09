import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CredentialManager } from "../credentials";
import { newSessionId } from "../id/id";
import type {
  RunControlRecord,
  RunControlStore,
} from "../runtime/runControlStore";
import type { RunModelStore } from "../runtime/runModelStore";
import type { RunRecoveryStore } from "../runtime/runRecoveryStore";
import {
  type RecordedRunSpec,
  RecordedRunSpecSchema,
  type RunRecord,
} from "../runtime/runStore";
import type { RunToolStore } from "../runtime/runToolStore";

const calls = vi.hoisted(() => [] as string[]);
const sessionCreate = vi.hoisted(() => vi.fn());
const runAgent = vi.hoisted(() => vi.fn());

vi.mock("../session", () => ({ create: sessionCreate }));
vi.mock("./offesecAgent", () => ({ runOffensiveSecurityAgent: runAgent }));

import { runRecordedAgent } from "./recordedRun";

const RUN_RESULT = { streamResult: {}, session: {} } as never;

function baseSpec(cwd: string, overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: 1,
    configVersion: 1,
    runId: "run_local_test_01",
    prompt: "Request the target homepage once and summarize the response.",
    target: "http://127.0.0.1:8080",
    model: "claude-sonnet-5-5",
    activeTools: ["http_request"],
    environment: { kind: "local", cwd },
    scope: {
      version: 1,
      allowedHosts: ["127.0.0.1"],
      allowedPorts: [8080],
      strictScope: true,
      allowDestructiveActions: false,
      allowRateLimitTesting: false,
    },
    credentialRefs: [],
    ...overrides,
  };
}

function makeRecord(spec: RecordedRunSpec): RunRecord {
  return {
    schemaVersion: 1,
    spec,
    sessionId: newSessionId(),
    attemptId: `exec_${randomUUID()}`,
    runtimeVersion: "test",
    status: "admitted",
    admittedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

function makeStore() {
  let record: RunRecord | undefined;
  let control: RunControlRecord | undefined;
  const transitionFailures = new Map<string, unknown>();
  const store: RunModelStore &
    RunToolStore &
    RunControlStore &
    RunRecoveryStore = {
    acquireExecutionLock: async (runId: string) => ({
      runId,
      release: vi.fn(),
    }),
    enrollRecovery: async () => ({}) as never,
    getRecoveryEnrollment: async () => undefined,
    listRecoveries: async () => [],
    claimRecovery: async () => {
      throw new Error("Unexpected recovery");
    },
    initializeControl: async (runId: string, executionAttemptId: string) => {
      control = {
        schemaVersion: 1,
        runId,
        executionAttemptId,
        intent: "run",
        revision: 0,
        updatedAt: new Date().toISOString(),
      };
    },
    getControl: async () => control,
    requestControl: async (
      _runId: string,
      intent: "pause" | "stop",
      revision: number,
    ) => {
      if (!control || control.revision !== revision)
        throw new Error("Control revision changed");
      control = { ...control, intent, revision: revision + 1 };
      return control;
    },
    requestApproval: async () => {
      throw new Error("Unexpected approval");
    },
    getApproval: async () => undefined,
    listApprovals: async () => [],
    resolveApproval: async () => {
      throw new Error("Unexpected approval");
    },
    initializeToolJournal: vi.fn(async () => {}),
    hasToolJournal: vi.fn(async () => true),
    startToolOperation: vi.fn(async () => {
      throw new Error("Unexpected tool dispatch");
    }),
    settleToolOperation: vi.fn(async () => {}),
    markToolOutcomeUnknown: vi.fn(async () => {}),
    listToolOperations: vi.fn(async () => []),
    startModelAttempt: vi.fn(async () => {}),
    observeModelToolCall: vi.fn(async () => {}),
    settleModelAttempt: vi.fn(async () => {}),
    recordRetry: vi.fn(async () => {}),
    listModelAttempts: vi.fn(async () => []),
    listRetries: vi.fn(async () => []),
    commitContext: vi.fn(async () => ({ epoch: 1, revision: 1 })),
    getContext: vi.fn(async () => undefined),
    getEvidence: vi.fn(async () => undefined),
    admit: vi.fn(async (spec: RecordedRunSpec) => {
      if (record) return { created: false, record };
      record = makeRecord(spec);
      calls.push("admit");
      return { created: true, record };
    }),
    get: vi.fn(async () => record),
    list: vi.fn(async () => (record ? [record] : [])),
    transition: vi.fn(
      async (
        _runId: string,
        attemptId: string,
        status: RunRecord["status"],
      ) => {
        const failure = transitionFailures.get(status);
        if (failure) {
          transitionFailures.delete(status);
          throw failure;
        }
        if (!record) throw new Error("Run does not exist");
        if (record.attemptId !== attemptId) throw new Error("Wrong attempt");
        record = { ...record, status, updatedAt: new Date().toISOString() };
        return record;
      },
    ),
  };
  return {
    store,
    current: () => record,
    failTransition: (status: string, error: unknown) =>
      transitionFailures.set(status, error),
  };
}

function makeManager(ids: string[]) {
  return {
    getReference: (id: string) => (ids.includes(id) ? { id } : undefined),
    listReferences: () => ids.map((id) => ({ id })),
  } as unknown as CredentialManager;
}

let tempDirs: string[];

function tempCwd(): string {
  const dir = mkdtempSync(join(tmpdir(), "recorded-run-cwd-"));
  tempDirs.push(dir);
  return dir;
}

beforeEach(() => {
  calls.length = 0;
  sessionCreate.mockReset();
  runAgent.mockReset();
  sessionCreate.mockImplementation(async (input: { id?: string }) => ({
    id: input.id,
    rootPath: "/fake/session/root",
  }));
  runAgent.mockResolvedValue(RUN_RESULT);
  tempDirs = [];
});

afterEach(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("admission commits before any session creation or inference", () => {
  it("admits, creates the session, marks running, then runs — in that order", async () => {
    const { store } = makeStore();
    const outcome = await runRecordedAgent({
      spec: baseSpec(tempCwd()),
      store,
    });

    expect(outcome.started).toBe(true);
    expect(outcome.result).toBe(RUN_RESULT);
    expect(calls).toEqual(["admit"]);
    expect(sessionCreate).toHaveBeenCalledTimes(1);
    expect(store.transition).toHaveBeenCalledWith(
      "run_local_test_01",
      expect.any(String),
      "running",
    );
    expect(
      (store.transition as ReturnType<typeof vi.fn>).mock.calls.at(-1)?.[2],
    ).toBe("completed");
    expect(outcome.record.status).toBe("completed");
  });
});

describe("duplicate admission never executes", () => {
  it("returns the existing record with started:false and no session or run", async () => {
    const { store } = makeStore();
    await runRecordedAgent({ spec: baseSpec(tempCwd()), store });
    const firstSessionCalls = sessionCreate.mock.calls.length;
    const firstRunCalls = runAgent.mock.calls.length;

    const outcome = await runRecordedAgent({
      spec: baseSpec("/any/cwd"), // duplicate check precedes cwd validation
      store,
    });

    expect(outcome.started).toBe(false);
    expect(sessionCreate.mock.calls.length).toBe(firstSessionCalls);
    expect(runAgent.mock.calls.length).toBe(firstRunCalls);
    expect(outcome.record.status).toBe("completed"); // existing, untouched
  });
});

describe("critical failures settle failed without dispatching the agent", () => {
  it("rejects journal enrollment failure before agent dispatch", async () => {
    const { store, current } = makeStore();
    vi.mocked(store.initializeToolJournal).mockRejectedValue(
      new Error("journal unavailable"),
    );
    await expect(
      runRecordedAgent({ spec: baseSpec(tempCwd()), store }),
    ).rejects.toThrow("journal unavailable");
    expect(runAgent).not.toHaveBeenCalled();
    expect(current()?.status).toBe("failed");
  });

  it("rejects an unregistered model before session creation", async () => {
    const { store, current } = makeStore();
    await expect(
      runRecordedAgent({
        spec: baseSpec(tempCwd(), { model: "not-a-registered-model" }),
        store,
      }),
    ).rejects.toThrow("Model is not registered");

    expect(sessionCreate).not.toHaveBeenCalled();
    expect(runAgent).not.toHaveBeenCalled();
    expect(current()?.status).toBe("failed");
  });

  it("rejects a missing cwd before session creation", async () => {
    const { store, current } = makeStore();
    await expect(
      runRecordedAgent({
        spec: baseSpec("/definitely/not/a/real/dir"),
        store,
      }),
    ).rejects.toThrow();

    expect(sessionCreate).not.toHaveBeenCalled();
    expect(runAgent).not.toHaveBeenCalled();
    expect(current()?.status).toBe("failed");
  });

  it("rejects a file supplied as the working directory", async () => {
    const file = join(tempCwd(), "file.txt");
    writeFileSync(file, "fixture");
    const { store, current } = makeStore();
    await expect(
      runRecordedAgent({ spec: baseSpec(file), store }),
    ).rejects.toThrow("not a directory");
    expect(sessionCreate).not.toHaveBeenCalled();
    expect(runAgent).not.toHaveBeenCalled();
    expect(current()?.status).toBe("failed");
  });

  it("rejects a credential reference the manager cannot resolve", async () => {
    const { store, current } = makeStore();
    await expect(
      runRecordedAgent({
        spec: baseSpec(tempCwd(), { credentialRefs: ["cred_missing"] }),
        store,
        credentialManager: makeManager([]),
      }),
    ).rejects.toThrow("Referenced credential is not available");

    expect(runAgent).not.toHaveBeenCalled();
    expect(current()?.status).toBe("failed");
  });

  it("rejects referenced credentials when no manager is provided", async () => {
    const { store } = makeStore();
    await expect(
      runRecordedAgent({
        spec: baseSpec(tempCwd(), { credentialRefs: ["cred_a"] }),
        store,
      }),
    ).rejects.toThrow("Referenced credential is not available");
    expect(runAgent).not.toHaveBeenCalled();
  });

  it("rejects a manager holding credentials the spec did not declare", async () => {
    const { store, current } = makeStore();
    await expect(
      runRecordedAgent({
        spec: baseSpec(tempCwd()),
        store,
        credentialManager: makeManager(["cred_undeclared"]),
      }),
    ).rejects.toThrow("undeclared credential");

    expect(runAgent).not.toHaveBeenCalled();
    expect(current()?.status).toBe("failed");
  });

  it("accepts exact credential declaration", async () => {
    const { store } = makeStore();
    const outcome = await runRecordedAgent({
      spec: baseSpec(tempCwd(), { credentialRefs: ["cred_a"] }),
      store,
      credentialManager: makeManager(["cred_a"]),
    });
    expect(outcome.record.status).toBe("completed");
  });
});

describe("pre-aborted signal cancels before execution", () => {
  it("settles cancelled without creating a session or running", async () => {
    const { store, current } = makeStore();
    const controller = new AbortController();
    controller.abort();

    const outcome = await runRecordedAgent({
      spec: baseSpec(tempCwd()),
      store,
      abortSignal: controller.signal,
    });

    expect(outcome.started).toBe(false);
    expect(outcome.result).toBeUndefined();
    expect(outcome.record.status).toBe("cancelled");
    expect(sessionCreate).not.toHaveBeenCalled();
    expect(runAgent).not.toHaveBeenCalled();
    expect(current()?.status).toBe("cancelled");
  });
});

describe("recorded context and evidence wiring", () => {
  it("commits evidence references with context before dependent work", async () => {
    const { store } = makeStore();
    const rootPath = tempCwd();
    writeFileSync(join(rootPath, "plan.md"), "Assess local target");
    sessionCreate.mockResolvedValue({
      rootPath,
      findingsPath: join(rootPath, "findings"),
      logsPath: join(rootPath, "logs"),
      pocsPath: join(rootPath, "pocs"),
    });
    runAgent.mockImplementationOnce(async ({ contextRecorder }) => {
      await contextRecorder.checkpoint({
        messages: [{ role: "user", content: "objective" }],
        system: "scope",
      });
      calls.push("dependent-work");
      return RUN_RESULT;
    });
    await runRecordedAgent({ spec: baseSpec(rootPath), store });
    expect(store.commitContext).toHaveBeenCalledWith(
      "run_local_test_01",
      expect.stringMatching(/^exec_/),
      0,
      {
        kind: "replace",
        system: "scope",
        messages: [{ role: "user", content: "objective" }],
      },
      {
        rootPath,
        files: [
          {
            path: "plan.md",
            bytes: 19,
            sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
          },
        ],
      },
    );
    expect(calls).toContain("dependent-work");
  });

  it("fails the run when a context write prevents dependent work", async () => {
    const { store, current } = makeStore();
    const rootPath = tempCwd();
    sessionCreate.mockResolvedValue({
      rootPath,
      findingsPath: join(rootPath, "findings"),
      logsPath: join(rootPath, "logs"),
      pocsPath: join(rootPath, "pocs"),
    });
    vi.mocked(store.commitContext).mockRejectedValueOnce(
      new Error("disk full"),
    );
    runAgent.mockImplementationOnce(async ({ contextRecorder }) => {
      await contextRecorder.checkpoint({
        messages: [{ role: "user", content: "objective" }],
      });
      calls.push("dependent-work");
      return RUN_RESULT;
    });
    await expect(
      runRecordedAgent({ spec: baseSpec(rootPath), store }),
    ).rejects.toThrow(/persistence failed/);
    expect(calls).not.toContain("dependent-work");
    expect(current()?.status).toBe("failed");
  });
});

describe("the admitted, normalized spec drives execution", () => {
  it("applies defaults and forwards the parsed spec to the session and agent", async () => {
    const cwd = tempCwd();
    const raw = baseSpec(cwd, {
      runId: "run_normalized_01",
      system: "custom system prompt",
      activeTools: ["http_request", "create_task", "list_tasks"],
      scope: {
        version: 1,
        allowedHosts: ["127.0.0.1"],
        allowedPorts: [8080],
        strictScope: true,
      },
      // credentialRefs omitted → defaults to []
    });
    const { store } = makeStore();

    await runRecordedAgent({ spec: raw, store });

    // admit received the normalized spec, not the raw input
    const admitted = (store.admit as ReturnType<typeof vi.fn>).mock
      .calls[0][0] as RecordedRunSpec;
    expect(admitted.credentialRefs).toEqual([]);
    expect(admitted.scope.allowDestructiveActions).toBe(false);
    expect(admitted.scope.allowRateLimitTesting).toBe(false);

    const sessionInput = sessionCreate.mock.calls[0][0];
    expect(sessionInput.id).toMatch(/^ses_/);
    expect(sessionInput.targets).toEqual(["http://127.0.0.1:8080"]);
    expect(sessionInput.name).toBe("run_normalized_01");
    expect(sessionInput.inheritEnvironmentConfig).toBe(false);
    expect(sessionInput.config).toEqual({
      headers: {},
      agentCwd: cwd,
      scopeConstraints: {
        allowedHosts: ["127.0.0.1"],
        allowedPorts: [8080],
        strictScope: true,
      },
      allowDestructiveActions: false,
      allowRateLimitTesting: false,
      taskDriven: true,
      disableSubagents: true,
    });

    const agentInput = runAgent.mock.calls[0][0];
    expect(agentInput.prompt).toBe(raw.prompt);
    expect(agentInput.model).toBe("claude-sonnet-5-5");
    expect(agentInput.system).toBe("custom system prompt");
    expect(agentInput.activeTools).toEqual([
      "http_request",
      "create_task",
      "list_tasks",
    ]);
    expect(agentInput.target).toBe("http://127.0.0.1:8080");
    expect(agentInput.agentCwd).toBe(cwd);
    // no early-result resolver, no subagent spawner, no sandbox
    expect(agentInput.resolveResult).toBeUndefined();
    expect(agentInput.subagentSpawner).toBeUndefined();
    expect(agentInput.sandbox).toBeUndefined();
  });

  it("omits system when the spec has none", async () => {
    const { store } = makeStore();
    await runRecordedAgent({ spec: baseSpec(tempCwd()), store });
    expect("system" in runAgent.mock.calls[0][0]).toBe(false);
  });
});

describe("runtime hooks pass through by identity", () => {
  it("forwards credentials and events with a runtime-owned cancellation signal", async () => {
    const { store } = makeStore();
    const eventBus = { on: () => {}, emit: () => {} } as never;
    const controller = new AbortController();
    const authConfig = { apiKey: "redacted" } as never;
    const credentialManager = makeManager([]);

    await runRecordedAgent({
      spec: baseSpec(tempCwd()),
      store,
      eventBus,
      abortSignal: controller.signal,
      authConfig,
      credentialManager,
    });

    const agentInput = runAgent.mock.calls[0][0];
    expect(agentInput.eventBus).toBe(eventBus);
    expect(agentInput.abortSignal).toBeInstanceOf(AbortSignal);
    expect(agentInput.abortSignal.aborted).toBe(false);
    expect(agentInput.authConfig).toBe(authConfig);
    expect(agentInput.credentialManager).toBe(credentialManager);
  });

  it("omits optional hooks when not provided", async () => {
    const { store } = makeStore();
    await runRecordedAgent({ spec: baseSpec(tempCwd()), store });
    const agentInput = runAgent.mock.calls[0][0];
    expect("eventBus" in agentInput).toBe(false);
    expect(agentInput.abortSignal).toBeInstanceOf(AbortSignal);
    expect("authConfig" in agentInput).toBe(false);
    expect("credentialManager" in agentInput).toBe(false);
  });
});

describe("settlement on failure", () => {
  it("settles failed and rethrows the original execution error", async () => {
    const { store, current } = makeStore();
    const sentinel = new Error("agent stream failed");
    runAgent.mockRejectedValueOnce(sentinel);

    await expect(
      runRecordedAgent({ spec: baseSpec(tempCwd()), store }),
    ).rejects.toBe(sentinel);

    expect(current()?.status).toBe("failed");
  });

  it("settles cancelled when the signal aborted mid-run", async () => {
    const { store, current } = makeStore();
    const controller = new AbortController();
    runAgent.mockImplementationOnce(async () => {
      controller.abort();
      throw new DOMException("Aborted", "AbortError");
    });

    await expect(
      runRecordedAgent({
        spec: baseSpec(tempCwd()),
        store,
        abortSignal: controller.signal,
      }),
    ).rejects.toBeInstanceOf(DOMException);

    expect(current()?.status).toBe("cancelled");
  });

  it("records an agent AbortError as cancelled without an external signal", async () => {
    const { store, current } = makeStore();
    const error = new DOMException("Aborted", "AbortError");
    runAgent.mockRejectedValueOnce(error);
    await expect(
      runRecordedAgent({ spec: baseSpec(tempCwd()), store }),
    ).rejects.toBe(error);
    expect(current()?.status).toBe("cancelled");
  });

  it("throws AggregateError when the status write also fails, preserving both", async () => {
    const { store, failTransition } = makeStore();
    const original = new Error("execution exploded");
    const writeFailure = new Error("status write failed");
    runAgent.mockRejectedValueOnce(original);
    failTransition("failed", writeFailure);

    const caught = await runRecordedAgent({
      spec: baseSpec(tempCwd()),
      store,
    }).catch((err) => err);

    expect(caught).toBeInstanceOf(AggregateError);
    expect((caught as AggregateError).errors).toEqual([original, writeFailure]);
  });

  it("does not fake a failed status after a completed write fails", async () => {
    const { store, current, failTransition } = makeStore();
    const writeFailure = new Error("completed write failed");
    failTransition("completed", writeFailure);

    await expect(
      runRecordedAgent({ spec: baseSpec(tempCwd()), store }),
    ).rejects.toBe(writeFailure);

    // Exactly one terminal write attempt (running + completed), never a
    // retried "failed" — the last committed status stays "running".
    const statuses = (
      store.transition as ReturnType<typeof vi.fn>
    ).mock.calls.map((c) => c[2]);
    expect(statuses).toEqual(["running", "completed"]);
    expect(current()?.status).toBe("running");
  });
});

describe("spec parsing", () => {
  it("rejects an invalid spec before touching the store", async () => {
    const { store } = makeStore();
    await expect(
      runRecordedAgent({
        spec: { ...baseSpec(tempCwd()), runId: "bad id with spaces" },
        store,
      }),
    ).rejects.toThrow();
    expect(store.admit).not.toHaveBeenCalled();
  });

  it("rejects tools outside the recorded-run allowlist", async () => {
    const { store } = makeStore();
    await expect(
      runRecordedAgent({
        spec: baseSpec(tempCwd(), { activeTools: ["spawn_pentest_agent"] }),
        store,
      }),
    ).rejects.toThrow();
    expect(store.admit).not.toHaveBeenCalled();
  });
});

describe("RecordedRunSpecSchema normalization is idempotent", () => {
  it("re-parsing an admitted spec yields the identical normalized shape", () => {
    const cwd = tempCwd();
    const parsed = RecordedRunSpecSchema.parse(baseSpec(cwd));
    expect(RecordedRunSpecSchema.parse(parsed)).toEqual(parsed);
  });
});
