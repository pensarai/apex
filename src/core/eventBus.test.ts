import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TextStreamPart, ToolSet } from "ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { StepTraceWriter, type TraceRecord } from "./agents/offSecAgent/trace";
import { AgentEventBus, type StreamIdContext } from "./eventBus";
import { isPartId, newMessageId, newSessionId } from "./id/id";

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

// ---------------------------------------------------------------------------
// Native identity threading: emitStreamPart stamps sessionId / messageId /
// partId, and attachChild injects the child's session id + parentSessionId.
// ---------------------------------------------------------------------------

describe("emitStreamPart — native id threading", () => {
  function part(chunk: Partial<TextStreamPart<ToolSet>> & { type: string }) {
    return chunk as TextStreamPart<ToolSet>;
  }

  it("stamps sessionId/messageId/partId on text and tool events", () => {
    const bus = new AgentEventBus();
    const sessionId = newSessionId();
    const messageId = newMessageId();
    const toolPartIds = new Map<string, string>();
    let nextPart = 0;

    const ids: StreamIdContext = {
      subagentId: sessionId,
      sessionId,
      messageId,
      textPartId: "prt_textrun",
      toolPartId: (toolCallId: string) => {
        let p = toolPartIds.get(toolCallId);
        if (!p) {
          p = `prt_tool_${nextPart++}`;
          toolPartIds.set(toolCallId, p);
        }
        return p;
      },
    };

    const text: AgentEventMapText[] = [];
    bus.on("text-delta", (e) => text.push(e));
    const starts: AgentEventMapToolStart[] = [];
    bus.on("tool-call-start", (e) => starts.push(e));
    const completes: AgentEventMapToolComplete[] = [];
    bus.on("tool-call-complete", (e) => completes.push(e));
    const results: AgentEventMapToolResult[] = [];
    bus.on("tool-result", (e) => results.push(e));

    bus.emitStreamPart(part({ type: "text-delta", id: "t1", text: "hi" }), ids);
    bus.emitStreamPart(
      part({ type: "tool-input-start", id: "tc-1", toolName: "exec" }),
      ids,
    );
    bus.emitStreamPart(
      part({
        type: "tool-call",
        toolCallId: "tc-1",
        toolName: "exec",
        input: { cmd: "ls" },
      }),
      ids,
    );
    bus.emitStreamPart(
      part({
        type: "tool-result",
        toolCallId: "tc-1",
        toolName: "exec",
        output: "ok",
      }),
      ids,
    );

    expect(text[0]).toMatchObject({
      sessionId,
      messageId,
      partId: "prt_textrun",
    });

    // Tool start mints a part id; complete + result reuse the SAME part id.
    expect(starts[0]).toMatchObject({ sessionId, messageId });
    const toolPartId = starts[0].partId;
    expect(toolPartId).toBeDefined();
    expect(completes[0].partId).toBe(toolPartId);
    expect(results[0].partId).toBe(toolPartId);
  });

  it("accepts a bare subagentId string for backward compatibility", () => {
    const bus = new AgentEventBus();
    const received: AgentEventMapText[] = [];
    bus.on("text-delta", (e) => received.push(e));

    bus.emitStreamPart(
      part({ type: "text-delta", id: "t1", text: "x" }),
      "sub-1",
    );

    expect(received[0].subagentId).toBe("sub-1");
    expect(received[0].sessionId).toBeUndefined();
  });
});

describe("attachChild — session id injection", () => {
  it("injects the child session id as sessionId + subagentId on forwarded events", () => {
    const parent = new AgentEventBus();
    const child = new AgentEventBus();
    const childSessionId = newSessionId();
    AgentEventBus.attachChild(child, parent, childSessionId);

    const received: { sessionId?: string; subagentId?: string }[] = [];
    parent.on("text-delta", (e) => received.push(e));

    child.emit("text-delta", { text: "from child" });

    expect(received).toHaveLength(1);
    expect(received[0].sessionId).toBe(childSessionId);
    expect(received[0].subagentId).toBe(childSessionId);
  });

  it("injects parentSessionId on bubbled lifecycle events", () => {
    const parent = new AgentEventBus();
    const child = new AgentEventBus();
    const childSessionId = newSessionId();
    AgentEventBus.attachChild(child, parent, childSessionId);

    const received: { parentSessionId?: string; sessionId?: string }[] = [];
    parent.on("subagent-spawn", (e) => received.push(e));

    const grandchildSessionId = newSessionId();
    child.emit("subagent-spawn", {
      subagentId: grandchildSessionId,
      sessionId: grandchildSessionId,
      input: {},
    });

    expect(received).toHaveLength(1);
    // The grandchild's own session id is preserved...
    expect(received[0].sessionId).toBe(grandchildSessionId);
    // ...and the child (this bus's owner) becomes the parent.
    expect(received[0].parentSessionId).toBe(childSessionId);
  });
});

// Local payload aliases so the test bodies stay readable without importing
// the (intentionally not exported) AgentEventMap.
type AgentEventMapText = {
  text: string;
  sessionId?: string;
  subagentId?: string;
  messageId?: string;
  partId?: string;
};
type AgentEventMapToolStart = {
  toolCallId: string;
  toolName: string;
  sessionId?: string;
  messageId?: string;
  partId?: string;
};
type AgentEventMapToolComplete = AgentEventMapToolStart & { args: unknown };
type AgentEventMapToolResult = AgentEventMapToolStart & { result: unknown };

// Reference isPartId so the import is exercised as a sanity assertion.
describe("partId shape", () => {
  it("minted tool/text part ids are prt_-prefixed", () => {
    const bus = new AgentEventBus();
    const got: string[] = [];
    bus.on("tool-call-start", (e) => {
      if (e.partId) got.push(e.partId);
    });
    let n = 0;
    bus.emitStreamPart(
      {
        type: "tool-input-start",
        id: "tc-x",
        toolName: "t",
      } as TextStreamPart<ToolSet>,
      {
        sessionId: newSessionId(),
        toolPartId: () => {
          n++;
          return `prt_x${n}`;
        },
      },
    );
    expect(got).toHaveLength(1);
    expect(isPartId(got[0])).toBe(true);
  });
});
