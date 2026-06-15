import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { StepTraceWriter, type TraceRecord } from "./agents/offSecAgent/trace";
import { AgentEventBus } from "./eventBus";

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

  // Lifecycle hierarchy: a subagent-spawn emitted on a child bus without an
  // explicit parent must arrive at the parent bus anchored to the child's
  // subagentId. This is what nests e.g. the Finding Judge under the pentest
  // worker that invoked document_vulnerability.
  it("injects parentSubagentId on lifecycle events crossing the child→parent boundary", () => {
    const parent = new AgentEventBus();
    const child = new AgentEventBus();
    AgentEventBus.attachChild(child, parent, "pentest-agent-worker-1");

    const spawns: { subagentId: string; parentSubagentId?: string }[] = [];
    const completes: { subagentId: string; parentSubagentId?: string }[] = [];
    parent.on("subagent-spawn", (e) => spawns.push(e));
    parent.on("subagent-complete", (e) => completes.push(e));

    child.emit("subagent-spawn", {
      subagentId: "finding-judge-1",
      name: "Finding Judge",
      input: null,
    });
    child.emit("subagent-complete", {
      subagentId: "finding-judge-1",
      status: "completed",
    });

    expect(spawns).toHaveLength(1);
    expect(spawns[0].parentSubagentId).toBe("pentest-agent-worker-1");
    expect(completes).toHaveLength(1);
    expect(completes[0].parentSubagentId).toBe("pentest-agent-worker-1");
  });

  // Lifecycle hierarchy across nested hops: once a parent has been assigned
  // (explicitly or by the first attachChild hop), outer hops must not
  // overwrite it — otherwise deep nesting flattens to the outermost agent.
  it("preserves an existing parentSubagentId on lifecycle events across nested hops", () => {
    const root = new AgentEventBus();
    const mid = new AgentEventBus();
    const leaf = new AgentEventBus();
    AgentEventBus.attachChild(mid, root, "outer");
    AgentEventBus.attachChild(leaf, mid, "inner");

    const spawns: { subagentId: string; parentSubagentId?: string }[] = [];
    root.on("subagent-spawn", (e) => spawns.push(e));

    leaf.emit("subagent-spawn", {
      subagentId: "inner-finding-judge-1",
      name: "Finding Judge",
      input: null,
    });

    expect(spawns).toHaveLength(1);
    expect(spawns[0].parentSubagentId).toBe("inner");
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
