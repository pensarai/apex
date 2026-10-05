import { createHash } from "node:crypto";
import type { ModelMessage } from "ai";
import { beforeEach, describe, expect, it } from "vitest";
import type { RecordedApproval } from "./runControlStore";
import type { RecordedModelAttempt, RecordedRetry } from "./runModelStore";
import type { RecoveryPlanContext, RecoveryPlanInput } from "./runRecoveryPlan";
import { planRunRecovery } from "./runRecoveryPlan";
import type { RecoveryRecord } from "./runRecoveryStore";
import type { RunRecord } from "./runStore";
import type { RecordedToolOperation } from "./runToolStore";

// ---------------------------------------------------------------------------
// Fixtures. IDs follow the real envelope shapes (atm_/idem_/exec_/ses_) so
// plans are exercised against production-like data.
// ---------------------------------------------------------------------------

const ATTEMPT_ID = "exec_00000000-0000-4000-8000-000000000001";

function makeRecord(model = "claude-sonnet-5"): RunRecord {
  return {
    schemaVersion: 1,
    sessionId: "ses_0123456789abcdef",
    attemptId: ATTEMPT_ID,
    runtimeVersion: "test",
    status: "running",
    admittedAt: "2026-10-05T00:00:00.000Z",
    updatedAt: "2026-10-05T00:00:00.000Z",
    spec: {
      schemaVersion: 1,
      configVersion: 1,
      runId: "run_recovery_plan",
      prompt: "test the target",
      target: "http://127.0.0.1:8080",
      model,
      activeTools: ["http_request"],
      environment: { kind: "local", cwd: "/tmp/workspace" },
      scope: {
        version: 1,
        allowedHosts: ["127.0.0.1"],
        allowedPorts: [8080],
        strictScope: true,
        allowDestructiveActions: false,
        allowRateLimitTesting: false,
      },
      credentialRefs: [],
    },
  } as unknown as RunRecord;
}

function makeContext(
  revision = 2,
  messages: ModelMessage[] = [{ role: "user", content: "test the target" }],
  epoch = 1,
): RecoveryPlanContext {
  return { epoch, revision, messages, system: null };
}

let attemptCounter = 0;

function makeAttemptEntry(
  overrides: {
    lifecycle?: RecordedModelAttempt["attempt"]["lifecycle"];
    sequence?: number;
    context?: { epoch: number; revision: number } | null;
    toolCalls?: Array<{ toolCallId: string; toolName: string }>;
    startedAt?: string;
  } = {},
): RecordedModelAttempt {
  attemptCounter++;
  return {
    schemaVersion: 1,
    attempt: {
      schema: "pensar.inference_attempt",
      version: 1,
      attemptId: `atm_${String(attemptCounter).padStart(4, "0")}`,
      idempotencyKey: `idem_${String(attemptCounter).padStart(4, "0")}`,
      lifecycle: overrides.lifecycle ?? "completed",
      operationKind: "agent.stream",
      lineage: { sequence: overrides.sequence ?? 1 },
      attribution: {
        rootAttemptId: `atm_${String(attemptCounter).padStart(4, "0")}`,
      },
      requested: { provider: "anthropic", modelId: "claude-sonnet-5" },
      effective: { provider: "anthropic", modelId: "claude-sonnet-5" },
      tokens: {
        inclusiveInput: null,
        uncachedInput: null,
        cacheRead: null,
        cacheWrite: null,
        output: null,
      },
      evidence: {},
    },
    context:
      overrides.context === undefined
        ? { epoch: 1, revision: 1 }
        : overrides.context,
    toolCalls: overrides.toolCalls ?? [],
    startedAt: overrides.startedAt ?? "2026-10-05T00:00:01.000Z",
    updatedAt: "2026-10-05T00:00:02.000Z",
  } as unknown as RecordedModelAttempt;
}

let opCounter = 0;

function makeOperation(
  overrides: Partial<RecordedToolOperation> & { toolCallId: string },
): RecordedToolOperation {
  opCounter++;
  return {
    schemaVersion: 1,
    operationId: `top_00000000-0000-4000-8000-${String(opCounter).padStart(12, "0")}`,
    executionAttemptId: ATTEMPT_ID,
    toolName: "http_request",
    input: { url: "http://127.0.0.1:8080/" },
    policy: "external_effect",
    context: { epoch: 1, revision: 2 },
    state: "settled",
    output: { type: "json", value: { status: 200 } },
    startedAt: "2026-10-05T00:00:03.000Z",
    updatedAt: "2026-10-05T00:00:04.000Z",
    ...overrides,
  } as RecordedToolOperation;
}

let approvalCounter = 0;

function makeApproval(
  overrides: Partial<RecordedApproval> & { toolCallId: string },
): RecordedApproval {
  approvalCounter++;
  return {
    schemaVersion: 1,
    approvalId: `00000000-0000-4000-8000-${String(approvalCounter).padStart(12, "0")}`,
    runId: "run_recovery_plan",
    executionAttemptId: ATTEMPT_ID,
    toolName: "http_request",
    input: { url: "http://127.0.0.1:8080/" },
    specDigest: createHash("sha256")
      .update(JSON.stringify(makeRecord().spec))
      .digest("hex"),
    context: { epoch: 1, revision: 2 },
    state: "denied",
    createdAt: "2026-10-05T00:00:02.500Z",
    decidedAt: "2026-10-05T00:00:03.500Z",
    ...overrides,
  } as RecordedApproval;
}

function makeRecovery(
  fromAttemptId: string,
  toAttemptId: string,
): RecoveryRecord {
  return {
    schemaVersion: 1,
    recoveryId: `rec_${fromAttemptId}_${toAttemptId}`,
    runId: "run_recovery_plan",
    claimedAt: "2026-10-05T00:00:09.000Z",
    fromAttemptId,
    toAttemptId,
    fromContext: { epoch: 1, revision: 2 },
    input: {
      expectedAttemptId: fromAttemptId,
      expectedContext: { epoch: 1, revision: 2 },
      expectedControlRevision: 0,
      reconstruction: {
        sourceContext: { epoch: 1, revision: 2 },
        reconstructedToolCalls: [],
        restartedModelAttempts: [],
        deniedToolCalls: [],
        discardedUncommitted: false,
      },
    },
  } as unknown as RecoveryRecord;
}

function plan(input: Partial<RecoveryPlanInput> & { record?: RunRecord }) {
  return planRunRecovery({
    record: input.record ?? makeRecord(),
    context: input.context ?? makeContext(),
    attempts: input.attempts ?? [],
    operations: input.operations ?? [],
    approvals: input.approvals ?? [],
    retries: input.retries ?? [],
    recoveries: input.recoveries ?? [],
    ...input,
  });
}

beforeEach(() => {
  attemptCounter = 0;
  opCounter = 0;
  approvalCounter = 0;
});

describe("clean continuation", () => {
  it("returns the canonical head unchanged when every effect is reflected", () => {
    const context = makeContext(3);
    const result = plan({
      context,
      attempts: [
        makeAttemptEntry({ context: { epoch: 1, revision: 1 } }),
        makeAttemptEntry({
          context: { epoch: 1, revision: 2 },
          toolCalls: [{ toolCallId: "tc_settled", toolName: "http_request" }],
        }),
      ],
      operations: [
        makeOperation({
          toolCallId: "tc_settled",
          context: { epoch: 1, revision: 2 },
        }),
      ],
      approvals: [],
    });
    expect(result).toEqual({
      ok: true,
      messages: context.messages,
      reconstruction: {
        sourceContext: { epoch: 1, revision: 3 },
        reconstructedToolCalls: [],
        restartedModelAttempts: [],
        deniedToolCalls: [],
        discardedUncommitted: false,
      },
    });
  });
});

describe("current-revision exchange reconstruction", () => {
  it("refuses a denial bound to a different admitted scope", () => {
    const result = plan({
      attempts: [
        makeAttemptEntry({
          context: { epoch: 1, revision: 2 },
          toolCalls: [{ toolCallId: "tc_denied", toolName: "http_request" }],
        }),
      ],
      approvals: [
        makeApproval({ toolCallId: "tc_denied", specDigest: "f".repeat(64) }),
      ],
    });
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.blockers).toContainEqual(
        expect.stringContaining("admitted run and scope"),
      );
  });

  it("refuses distinct uncommitted exchanges even when timestamps match", () => {
    const result = plan({
      attempts: ["tc_a", "tc_b"].map((toolCallId) =>
        makeAttemptEntry({
          context: { epoch: 1, revision: 2 },
          toolCalls: [{ toolCallId, toolName: "http_request" }],
        }),
      ),
      operations: ["tc_a", "tc_b"].map((toolCallId) =>
        makeOperation({ toolCallId }),
      ),
    });
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.blockers).toContainEqual(
        expect.stringContaining("ordering is ambiguous"),
      );
  });

  it("synthesizes settled parallel exchanges in emission order with an interruption note", () => {
    // The issuing attempt emitted tc_b before tc_a; ops arrive reversed.
    const context = makeContext(2);
    const result = plan({
      context,
      attempts: [
        makeAttemptEntry({
          lifecycle: "started",
          context: { epoch: 1, revision: 2 },
          toolCalls: [
            { toolCallId: "tc_b", toolName: "http_request" },
            { toolCallId: "tc_a", toolName: "http_request" },
          ],
        }),
      ],
      operations: [
        makeOperation({ toolCallId: "tc_a", input: { url: "/a" } }),
        makeOperation({
          toolCallId: "tc_b",
          input: { url: "/b" },
          output: { type: "json", value: { status: 201 } },
        }),
      ],
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const [assistant, tool, note] = result.messages.slice(1);
    expect(assistant).toMatchObject({
      role: "assistant",
      content: [
        { type: "tool-call", toolCallId: "tc_b", input: { url: "/b" } },
        { type: "tool-call", toolCallId: "tc_a", input: { url: "/a" } },
      ],
    });
    expect(tool).toMatchObject({
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolCallId: "tc_b",
          output: { type: "json", value: { status: 201 } },
        },
        {
          type: "tool-result",
          toolCallId: "tc_a",
          output: { type: "json", value: { status: 200 } },
        },
      ],
    });
    expect(note).toMatchObject({
      role: "user",
      content: expect.stringContaining("Recovery note"),
    });
    expect(result.reconstruction).toEqual({
      sourceContext: { epoch: 1, revision: 2 },
      reconstructedToolCalls: [
        { toolCallId: "tc_b", operationId: expect.stringMatching(/^top_/) },
        { toolCallId: "tc_a", operationId: expect.stringMatching(/^top_/) },
      ],
      restartedModelAttempts: [],
      deniedToolCalls: [],
      discardedUncommitted: true,
    });
  });

  it("reconstructs denied approvals as deterministic blocked results", () => {
    const result = plan({
      attempts: [
        makeAttemptEntry({
          lifecycle: "started",
          context: { epoch: 1, revision: 2 },
          toolCalls: [{ toolCallId: "tc_d", toolName: "http_request" }],
        }),
      ],
      approvals: [
        makeApproval({
          toolCallId: "tc_d",
          state: "denied",
          reason: "user_rejected",
        }),
      ],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const tool = result.messages.at(-2);
    expect(tool).toMatchObject({
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolCallId: "tc_d",
          output: {
            type: "json",
            value: { blocked: true, reason: "Denied by operator" },
          },
        },
      ],
    });
    expect(result.reconstruction.deniedToolCalls).toEqual(["tc_d"]);
    expect(result.reconstruction.reconstructedToolCalls).toEqual([]);
  });

  it("skips operations from compacted, already-reflected epochs", () => {
    const result = plan({
      context: makeContext(3, undefined, 2),
      attempts: [
        makeAttemptEntry({
          context: { epoch: 1, revision: 1 },
          toolCalls: [{ toolCallId: "tc_old", toolName: "http_request" }],
        }),
      ],
      operations: [
        makeOperation({
          toolCallId: "tc_old",
          context: { epoch: 1, revision: 1 },
        }),
      ],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.messages).toHaveLength(1);
    expect(result.reconstruction.reconstructedToolCalls).toEqual([]);
  });

  it("reconstructs a historical receipt after repeated claims without a context commit", () => {
    const prior = "exec_00000000-0000-4000-8000-000000000002";
    const intermediate = "exec_00000000-0000-4000-8000-000000000003";
    const result = plan({
      recoveries: [
        makeRecovery(prior, intermediate),
        makeRecovery(intermediate, ATTEMPT_ID),
      ],
      attempts: [
        makeAttemptEntry({
          lifecycle: "started",
          context: { epoch: 1, revision: 2 },
          toolCalls: [{ toolCallId: "tc_hist", toolName: "http_request" }],
        }),
      ],
      operations: [
        makeOperation({
          toolCallId: "tc_hist",
          executionAttemptId: prior,
          input: { url: "/hist" },
        }),
      ],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.messages.slice(1)).toHaveLength(3);
    expect(result.messages[1]).toMatchObject({
      role: "assistant",
      content: [{ type: "tool-call", toolCallId: "tc_hist" }],
    });
    expect(result.messages[3]).toMatchObject({
      role: "user",
      content: expect.stringContaining("Recovery note"),
    });
    expect(
      result.reconstruction.reconstructedToolCalls.map(
        (call) => call.toolCallId,
      ),
    ).toEqual(["tc_hist"]);
  });

  it("blocks reconstruction for thinking-bound and non-direct providers", () => {
    const base = {
      attempts: [
        makeAttemptEntry({
          lifecycle: "started",
          context: { epoch: 1, revision: 2 },
          toolCalls: [{ toolCallId: "tc_p", toolName: "http_request" }],
        }),
      ],
      operations: [makeOperation({ toolCallId: "tc_p" })],
    };
    const thinking = plan({
      ...base,
      record: makeRecord("claude-sonnet-5-5"),
    });
    expect(thinking.ok).toBe(false);
    if (thinking.ok) return;
    expect(thinking.blockers.join(" ")).toContain("thinking");

    const otherProvider = plan({
      ...base,
      record: makeRecord("some-unknown-model"),
    });
    expect(otherProvider.ok).toBe(false);
    if (otherProvider.ok) return;
    expect(otherProvider.blockers.join(" ")).toContain("continuity data");
  });
});

describe("zero-effect interrupted requests", () => {
  it("restarts from the last checkpoint with an explicit note for the discarded output", () => {
    const result = plan({
      attempts: [
        makeAttemptEntry({
          lifecycle: "started",
          context: { epoch: 1, revision: 2 },
          toolCalls: [],
        }),
      ],
    });
    expect(result).toMatchObject({
      ok: true,
      reconstruction: {
        restartedModelAttempts: [expect.stringMatching(/^atm_/)],
        discardedUncommitted: true,
        reconstructedToolCalls: [],
      },
    });
    // Restart-only recovery still tells the model what was discarded.
    if (!result.ok) return;
    expect(result.messages.at(-1)).toMatchObject({
      role: "user",
      content: expect.stringContaining("Recovery note"),
    });
  });

  it("does not restart attempts whose output already reached the context", () => {
    const result = plan({
      attempts: [
        makeAttemptEntry({ context: { epoch: 1, revision: 1 }, toolCalls: [] }),
      ],
    });
    expect(result).toMatchObject({
      ok: true,
      reconstruction: {
        restartedModelAttempts: [],
        discardedUncommitted: false,
      },
    });
  });
});

describe("blockers", () => {
  const expectBlocked = (input: Parameters<typeof plan>[0], needle: string) => {
    const result = plan(input);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.blockers.join(" | ")).toContain(needle);
  };

  it("blocks unsettled operations", () => {
    expectBlocked(
      {
        attempts: [
          makeAttemptEntry({
            toolCalls: [{ toolCallId: "tc_u", toolName: "http_request" }],
          }),
        ],
        operations: [
          makeOperation({
            toolCallId: "tc_u",
            state: "outcome_unknown",
            output: undefined,
          }),
        ],
      },
      "outcome_unknown",
    );
  });

  it("blocks any execute_command use, even settled and reflected", () => {
    expectBlocked(
      {
        operations: [
          makeOperation({
            toolCallId: "tc_cmd",
            toolName: "execute_command",
            policy: "shell_state",
            input: { command: "ls" },
            context: { epoch: 1, revision: 1 },
          }),
        ],
      },
      "execute_command",
    );
  });

  it("blocks pending approvals and approved-without-operation", () => {
    expectBlocked(
      {
        approvals: [
          makeApproval({
            toolCallId: "tc_pend",
            state: "pending",
            decidedAt: undefined,
          }),
        ],
      },
      "still pending",
    );
    expectBlocked(
      {
        approvals: [
          makeApproval({
            toolCallId: "tc_ap",
            state: "approved",
            reason: undefined,
          }),
        ],
      },
      "no committed operation",
    );
  });

  it("blocks retry rows, failed/retried attempts, and retry lineage", () => {
    const retry: RecordedRetry = {
      authority: "stream-rate-limit",
      count: 1,
      maxRetries: 20,
      delayMs: 1000,
      sequence: 1,
      scheduledAt: "2026-10-05T00:00:05.000Z",
      dueAt: "2026-10-05T00:00:06.000Z",
    };
    expectBlocked({ retries: [retry] }, "retry rows");
    expectBlocked(
      {
        attempts: [
          makeAttemptEntry({
            lifecycle: "failed",
            toolCalls: [{ toolCallId: "tc_x", toolName: "http_request" }],
          }),
        ],
        operations: [makeOperation({ toolCallId: "tc_x" })],
      },
      "failed",
    );
    expectBlocked(
      { attempts: [makeAttemptEntry({ lifecycle: "retried" })] },
      "retry lineage",
    );
    expectBlocked(
      { attempts: [makeAttemptEntry({ sequence: 2 })] },
      "lineage sequence 2",
    );
  });

  it("blocks unmatched observed calls and unmatched decisions", () => {
    expectBlocked(
      {
        attempts: [
          makeAttemptEntry({
            toolCalls: [{ toolCallId: "tc_orphan", toolName: "http_request" }],
          }),
        ],
      },
      "no operation and no denial",
    );
    expectBlocked(
      {
        approvals: [makeApproval({ toolCallId: "tc_ghost" })],
      },
      "no matching observed model call",
    );
  });

  it("blocks future context links and foreign current-revision owners", () => {
    expectBlocked(
      {
        operations: [
          makeOperation({
            toolCallId: "tc_f",
            context: { epoch: 1, revision: 99 },
          }),
        ],
      },
      "future context",
    );
    expectBlocked(
      {
        attempts: [
          makeAttemptEntry({
            toolCalls: [{ toolCallId: "tc_o", toolName: "http_request" }],
          }),
        ],
        operations: [
          makeOperation({
            toolCallId: "tc_o",
            executionAttemptId: "exec_00000000-0000-4000-8000-0000000000ff",
          }),
        ],
      },
      "unrelated execution attempt",
    );
  });

  it("blocks duplicate observed toolCallIds across attempts", () => {
    expectBlocked(
      {
        attempts: [
          makeAttemptEntry({
            toolCalls: [{ toolCallId: "tc_dup", toolName: "http_request" }],
          }),
          makeAttemptEntry({
            toolCalls: [{ toolCallId: "tc_dup", toolName: "http_request" }],
          }),
        ],
        operations: [makeOperation({ toolCallId: "tc_dup" })],
      },
      "appears on multiple attempts",
    );
  });

  it("blocks auxiliary attempts inside a reconstructable exchange", () => {
    const auxAttempt = makeAttemptEntry({
      lifecycle: "started",
      context: { epoch: 1, revision: 2 },
      toolCalls: [{ toolCallId: "tc_aux", toolName: "http_request" }],
    });
    (auxAttempt.attempt as { operationKind: string }).operationKind =
      "tool.repair";
    expectBlocked(
      {
        attempts: [auxAttempt],
        operations: [makeOperation({ toolCallId: "tc_aux" })],
      },
      "auxiliary attempt",
    );
  });

  it("blocks a stale epoch with equal revision between an operation and its attempt", () => {
    // The issuing attempt dispatched at epoch 2; the operation bound the
    // epoch-1 head with the same revision number — not a match.
    expectBlocked(
      {
        context: makeContext(2, undefined, 2),
        attempts: [
          makeAttemptEntry({
            context: { epoch: 2, revision: 2 },
            toolCalls: [{ toolCallId: "tc_st", toolName: "http_request" }],
          }),
        ],
        operations: [
          makeOperation({
            toolCallId: "tc_st",
            context: { epoch: 1, revision: 2 },
          }),
        ],
      },
      "does not match its observed attempt",
    );
  });

  it("blocks approvals bound to a different dispatch context than their attempt", () => {
    expectBlocked(
      {
        attempts: [
          makeAttemptEntry({
            context: { epoch: 1, revision: 3 },
            toolCalls: [{ toolCallId: "tc_ac", toolName: "http_request" }],
          }),
        ],
        approvals: [
          makeApproval({
            toolCallId: "tc_ac",
            context: { epoch: 1, revision: 2 },
          }),
        ],
      },
      "dispatch context",
    );
  });

  it("blocks duplicate operation and approval rows", () => {
    expectBlocked(
      {
        attempts: [
          makeAttemptEntry({
            toolCalls: [{ toolCallId: "tc_dop", toolName: "http_request" }],
          }),
        ],
        operations: [
          makeOperation({ toolCallId: "tc_dop" }),
          makeOperation({ toolCallId: "tc_dop" }),
        ],
      },
      "appears multiple times",
    );
    expectBlocked(
      {
        approvals: [
          makeApproval({ toolCallId: "tc_dap" }),
          makeApproval({ toolCallId: "tc_dap" }),
        ],
      },
      "duplicates a decision",
    );
  });

  it("blocks auxiliary attempts behind denied exchanges", () => {
    const auxAttempt = makeAttemptEntry({
      lifecycle: "started",
      context: { epoch: 1, revision: 2 },
      toolCalls: [{ toolCallId: "tc_aden", toolName: "http_request" }],
    });
    (auxAttempt.attempt as { operationKind: string }).operationKind =
      "context.summarize";
    expectBlocked(
      {
        attempts: [auxAttempt],
        approvals: [makeApproval({ toolCallId: "tc_aden" })],
      },
      "auxiliary attempt",
    );
  });

  it("blocks recovery records belonging to another run", () => {
    const foreign = makeRecovery("exec_aaa", ATTEMPT_ID);
    (foreign as { runId: string }).runId = "run_other";
    expectBlocked({ recoveries: [foreign] }, "belongs to another run");
  });

  it("blocks ambiguous recovery history", () => {
    expectBlocked(
      {
        recoveries: [
          makeRecovery("exec_aaa", ATTEMPT_ID),
          makeRecovery("exec_bbb", ATTEMPT_ID),
        ],
      },
      "ambiguous",
    );
  });

  it("blocks denied-with-operation contradictions and input mismatches", () => {
    expectBlocked(
      {
        attempts: [
          makeAttemptEntry({
            toolCalls: [{ toolCallId: "tc_c", toolName: "http_request" }],
          }),
        ],
        operations: [makeOperation({ toolCallId: "tc_c" })],
        approvals: [makeApproval({ toolCallId: "tc_c" })],
      },
      "was denied but operation",
    );
    expectBlocked(
      {
        attempts: [
          makeAttemptEntry({
            toolCalls: [{ toolCallId: "tc_m", toolName: "http_request" }],
          }),
        ],
        operations: [
          makeOperation({ toolCallId: "tc_m", input: { url: "/x" } }),
        ],
        approvals: [
          makeApproval({
            toolCallId: "tc_m",
            state: "approved",
            reason: undefined,
          }),
        ],
      },
      "input does not match",
    );
  });

  it("blocks settled operations without output and attempts without context links", () => {
    expectBlocked(
      {
        attempts: [
          makeAttemptEntry({
            toolCalls: [{ toolCallId: "tc_no", toolName: "http_request" }],
          }),
        ],
        operations: [makeOperation({ toolCallId: "tc_no", output: undefined })],
      },
      "no output",
    );
    expectBlocked(
      { attempts: [makeAttemptEntry({ context: null })] },
      "no context link",
    );
  });
});
