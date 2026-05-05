import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { AgentEventBus } from "./eventBus";
import { StepTraceWriter, type TraceRecord } from "./agents/offSecAgent/trace";

// ---------------------------------------------------------------------------
// Regression coverage for issue #707 — trace-record forwarding across
// AgentEventBus.attachChild. Each test pins a named invariant from the plan.
// ---------------------------------------------------------------------------

describe("AgentEventBus.attachChild — child→parent forwarding contract", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "eventbus-attachchild-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  // INV-3 + DS-1, DS-2: trace-record must reach the parent with subagentId set.
  it("forwards trace-record from child→parent with subagentId injected", () => {
    const parent = new AgentEventBus();
    const child = new AgentEventBus();
    AgentEventBus.attachChild(child, parent, "sub-1");

    const received: { record: TraceRecord; subagentId?: string }[] = [];
    parent.on("trace-record", (e) => received.push(e));

    const writer = new StepTraceWriter({
      tracePath: join(tmpDir, "sub.jsonl"),
      agentId: "sub-1",
      eventBus: child,
    });
    writer.writeInit({
      model: "test",
      systemPrompt: "subagent prompt",
      activeTools: [],
      sessionId: "ses_test",
    });

    expect(received).toHaveLength(1);
    expect(received[0].subagentId).toBe("sub-1");
    expect(received[0].record.type).toBe("init");
  });

  // INV-5 + DS-6: parent-only events stay on the child bus, never bubble up.
  // Guards PR #614's fix from being silently undone by a future broadening
  // of the policy.
  it("does NOT forward parent-only events across the child→parent boundary", () => {
    const parent = new AgentEventBus();
    const child = new AgentEventBus();
    AgentEventBus.attachChild(child, parent, "sub-1");

    const received: unknown[] = [];
    parent.on("workflow-phase-start", (e) => received.push(e));

    child.emit("workflow-phase-start", {
      phase: "discovery",
      label: "should-not-bubble",
    });

    expect(received).toHaveLength(0);
  });

  // INV-7: nested attachChild (grandchild → child → root) must preserve the
  // innermost subagentId on the root bus. StepTraceWriter self-tags every
  // record with its own agentId, so the W&B grouping convention relies on
  // this passthrough behaviour.
  it("preserves the innermost subagentId across nested attachChild hops", () => {
    const root = new AgentEventBus();
    const mid = new AgentEventBus();
    const leaf = new AgentEventBus();
    AgentEventBus.attachChild(mid, root, "outer");
    AgentEventBus.attachChild(leaf, mid, "inner");

    const received: { record: TraceRecord; subagentId?: string }[] = [];
    root.on("trace-record", (e) => received.push(e));

    const writer = new StepTraceWriter({
      tracePath: join(tmpDir, "leaf.jsonl"),
      agentId: "inner",
      eventBus: leaf,
    });
    writer.writeInit({
      model: "test",
      systemPrompt: "leaf prompt",
      activeTools: [],
      sessionId: "ses_test",
    });

    expect(received).toHaveLength(1);
    expect(received[0].subagentId).toBe("inner");
  });
});
