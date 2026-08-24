import { describe, expect, it, vi } from "vitest";
import type { TraceRecord } from "../../../core/agents/offSecAgent";
import { AgentEventBus } from "../../../core/eventBus";
import type { SessionInfo } from "../../../core/session";
import { RunTraceSession } from "./run-tracing";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeStepRecord(
  stepIndex: number,
  timestamp: string,
  usage = { inputTokens: 10, outputTokens: 5 },
): TraceRecord {
  return {
    type: "step",
    stepIndex,
    timestamp,
    agentId: "pentest-agent-1",
    observations: null,
    reasoning: null,
    text: null,
    toolCalls: [],
    usage,
    cumulativeUsage: { ...usage },
    durationMs: 1,
  } as unknown as TraceRecord;
}

function makeSession(): SessionInfo {
  return {
    id: "ses_test",
    rootPath: "/tmp/ses_test",
  } as unknown as SessionInfo;
}

// ---------------------------------------------------------------------------
// RunTraceSession
// ---------------------------------------------------------------------------

describe("RunTraceSession", () => {
  it("counts deduped subagent step tokens, ignoring orchestrator steps", () => {
    const bus = new AgentEventBus();
    const recordTokenUsage = vi.fn();
    const trace = new RunTraceSession(bus, {
      isCurrent: () => true,
      recordTokenUsage,
      attach: async () => async () => {},
    });

    bus.emit("trace-record", {
      record: makeStepRecord(0, "t0"),
      subagentId: "pentest-agent-1",
    });
    // Orchestrator step (no subagentId) — not counted here.
    bus.emit("trace-record", { record: makeStepRecord(0, "t0") });
    // Non-step record — ignored.
    bus.emit("trace-record", {
      record: { type: "checkpoint" } as unknown as TraceRecord,
      subagentId: "pentest-agent-1",
    });

    expect(recordTokenUsage).toHaveBeenCalledTimes(1);
    expect(recordTokenUsage).toHaveBeenCalledWith(10, 5, 0, 0);
  });

  it("dedupes a replayed early-buffer step so it is not double-counted", async () => {
    const bus = new AgentEventBus();
    const recordTokenUsage = vi.fn();
    let attached: ((e: { record: TraceRecord }) => void) | null = null;
    const trace = new RunTraceSession(bus, {
      isCurrent: () => true,
      recordTokenUsage,
      attach: async (_s, eventBus) => {
        attached = (e) => {
          // Real attach re-emits through the bus; here we just observe.
          void eventBus;
          void e;
        };
        return async () => {};
      },
    });

    // Emit before attach — buffered.
    const rec = makeStepRecord(1, "t1");
    bus.emit("trace-record", { record: rec, subagentId: "pentest-agent-1" });
    expect(recordTokenUsage).toHaveBeenCalledTimes(1);

    await trace.tryAttach(makeSession());

    // The early-buffer replay re-emits the same step — dedup key suppresses it.
    bus.emit("trace-record", { record: rec, subagentId: "pentest-agent-1" });
    expect(recordTokenUsage).toHaveBeenCalledTimes(1);
    expect(attached).not.toBeNull();
  });

  it("replays buffered records to the uploader on attach", async () => {
    const bus = new AgentEventBus();
    const received: TraceRecord[] = [];
    // Faithful to attachWandbToEventBus: the uploader subscribes inside attach
    // (before returning its cleanup), then tryAttach replays the buffer.
    const trace = new RunTraceSession(bus, {
      isCurrent: () => true,
      recordTokenUsage: () => {},
      attach: async (_s, eventBus) => {
        const handler = (e: { record: TraceRecord }) => received.push(e.record);
        eventBus.on("trace-record", handler);
        return async () => {
          eventBus.off("trace-record", handler);
        };
      },
    });

    const rec = makeStepRecord(2, "t2");
    bus.emit("trace-record", { record: rec, subagentId: "pentest-agent-1" });

    await trace.tryAttach(makeSession());

    expect(received).toContain(rec);
  });

  it("is idempotent — a second tryAttach is a no-op", async () => {
    const bus = new AgentEventBus();
    const attach = vi.fn(async () => async () => {});
    const trace = new RunTraceSession(bus, {
      isCurrent: () => true,
      recordTokenUsage: () => {},
      attach,
    });

    await trace.tryAttach(makeSession());
    await trace.tryAttach(makeSession());

    expect(attach).toHaveBeenCalledTimes(1);
  });

  it("drops records when the generation guard fails", () => {
    const bus = new AgentEventBus();
    const recordTokenUsage = vi.fn();
    const trace = new RunTraceSession(bus, {
      isCurrent: () => false, // stale generation
      recordTokenUsage,
      attach: async () => async () => {},
    });

    bus.emit("trace-record", {
      record: makeStepRecord(0, "t0"),
      subagentId: "pentest-agent-1",
    });

    expect(recordTokenUsage).not.toHaveBeenCalled();
  });

  it("cleanup detaches listeners and flushes the uploader exactly once", async () => {
    const bus = new AgentEventBus();
    const recordTokenUsage = vi.fn();
    const flush = vi.fn(async () => {});
    const trace = new RunTraceSession(bus, {
      isCurrent: () => true,
      recordTokenUsage,
      attach: async () => flush,
    });

    await trace.tryAttach(makeSession());
    await trace.cleanupRun();
    await trace.cleanupRun(); // second call is safe

    expect(flush).toHaveBeenCalledTimes(1);

    // After cleanup, the token listener is detached.
    bus.emit("trace-record", {
      record: makeStepRecord(3, "t3"),
      subagentId: "pentest-agent-1",
    });
    expect(recordTokenUsage).not.toHaveBeenCalled();
  });

  it("survives attach failure — buffers stop and cleanup is safe", async () => {
    const bus = new AgentEventBus();
    const trace = new RunTraceSession(bus, {
      isCurrent: () => true,
      recordTokenUsage: () => {},
      attach: async () => {
        throw new Error("attach boom");
      },
    });

    await trace.tryAttach(makeSession()); // swallow + log
    await expect(trace.cleanupRun()).resolves.toBeUndefined();
  });

  it("survives flush failure in cleanup without throwing", async () => {
    const bus = new AgentEventBus();
    const trace = new RunTraceSession(bus, {
      isCurrent: () => true,
      recordTokenUsage: () => {},
      attach: async () => async () => {
        throw new Error("flush boom");
      },
    });

    await trace.tryAttach(makeSession());
    await expect(trace.cleanupRun()).resolves.toBeUndefined();
  });
});
