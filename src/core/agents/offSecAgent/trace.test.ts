import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AgentEventBus } from "../../eventBus";
import {
  type AuxiliaryRecord,
  type InitRecord,
  type StateCheckpoint,
  type StepRecord,
  StepTraceWriter,
  type TraceRecord,
} from "./trace";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "trace-test-"));
}

function readTraceRecords(tracePath: string): TraceRecord[] {
  return readFileSync(tracePath, "utf-8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as TraceRecord);
}

function readStepRecords(tracePath: string): StepRecord[] {
  return readTraceRecords(tracePath).filter(
    (r): r is StepRecord => r.type === "step",
  );
}

/**
 * Build a minimal ModelMessage[] that simulates a multi-step agent run.
 * Step 0: assistant emits text + tool-call
 * Step 1: tool-result (from step 0) + assistant emits reasoning + tool-call
 * Step 2: tool-result (from step 1) + assistant emits text only (final)
 */
function buildMessages(): {
  afterStep0: ModelMessage[];
  afterStep1: ModelMessage[];
  afterStep2: ModelMessage[];
} {
  const step0Assistant: ModelMessage = {
    role: "assistant",
    content: [
      { type: "text", text: "Let me check the target." },
      {
        type: "tool-call",
        toolCallId: "tc_001",
        toolName: "http_request",
        input: { url: "https://example.com", method: "GET" },
      },
    ],
  };

  const step1ToolResult: ModelMessage = {
    role: "tool",
    content: [
      {
        type: "tool-result",
        toolCallId: "tc_001",
        toolName: "http_request",
        output: {
          type: "text",
          value: "HTTP 200 OK - <html>Hello World</html>",
        },
      },
    ],
  };

  const step1Assistant: ModelMessage = {
    role: "assistant",
    content: [
      {
        type: "reasoning",
        text: "The target is reachable. I should test for XSS.",
      },
      {
        type: "tool-call",
        toolCallId: "tc_002",
        toolName: "execute_command",
        input: {
          command: "curl -s 'https://example.com?q=<script>alert(1)</script>'",
        },
      },
    ],
  };

  const step2ToolResult: ModelMessage = {
    role: "tool",
    content: [
      {
        type: "tool-result",
        toolCallId: "tc_002",
        toolName: "execute_command",
        output: {
          type: "text",
          value: "HTTP 200 - reflected <script>alert(1)</script>",
        },
      },
    ],
  };

  const step2Assistant: ModelMessage = {
    role: "assistant",
    content: [
      {
        type: "text",
        text: "XSS vulnerability confirmed. Documenting finding.",
      },
    ],
  };

  return {
    afterStep0: [step0Assistant],
    afterStep1: [step0Assistant, step1ToolResult, step1Assistant],
    afterStep2: [
      step0Assistant,
      step1ToolResult,
      step1Assistant,
      step2ToolResult,
      step2Assistant,
    ],
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("StepTraceWriter", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("writes one JSON line per step with type discriminator", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });
    writer.recordStep(msgs.afterStep1, { inputTokens: 200, outputTokens: 80 });
    writer.recordStep(msgs.afterStep2, { inputTokens: 150, outputTokens: 60 });

    const records = readStepRecords(tracePath);
    expect(records).toHaveLength(3);
    for (const r of records) {
      expect(r.type).toBe("step");
    }
  });

  it("assigns monotonically increasing stepIndex starting at 0", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });
    writer.recordStep(msgs.afterStep1, { inputTokens: 200, outputTokens: 80 });
    writer.recordStep(msgs.afterStep2, { inputTokens: 150, outputTokens: 60 });

    const records = readStepRecords(tracePath);
    expect(records.map((r) => r.stepIndex)).toEqual([0, 1, 2]);
  });

  it("sets observations to null on step 0", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });

    const [step0] = readStepRecords(tracePath);
    expect(step0.observations).toBeNull();
  });

  it("extracts observations from tool-result parts on subsequent steps", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });
    writer.recordStep(msgs.afterStep1, { inputTokens: 200, outputTokens: 80 });

    const records = readStepRecords(tracePath);
    const step1 = records[1];
    expect(step1.observations).not.toBeNull();
    expect(step1.observations).toHaveLength(1);
    expect(step1.observations?.[0].toolCallId).toBe("tc_001");
    expect(step1.observations?.[0].toolName).toBe("http_request");
    expect(step1.observations?.[0].outputType).toBe("text");
    expect(step1.observations?.[0].outputPreview).toContain("HTTP 200 OK");
  });

  it("extracts text from text parts", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });

    const [step0] = readStepRecords(tracePath);
    expect(step0.text).toBe("Let me check the target.");
  });

  it("extracts reasoning from reasoning parts", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });
    writer.recordStep(msgs.afterStep1, { inputTokens: 200, outputTokens: 80 });

    const records = readStepRecords(tracePath);
    expect(records[1].reasoning).toContain("The target is reachable");
  });

  it("extracts actions from tool-call parts", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });

    const [step0] = readStepRecords(tracePath);
    expect(step0.actions).toHaveLength(1);
    expect(step0.actions[0].toolCallId).toBe("tc_001");
    expect(step0.actions[0].toolName).toBe("http_request");
    expect(step0.actions[0].inputPreview).toContain("example.com");
  });

  it("returns empty actions array when model emits only text", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });
    writer.recordStep(msgs.afterStep1, { inputTokens: 200, outputTokens: 80 });
    writer.recordStep(msgs.afterStep2, { inputTokens: 150, outputTokens: 60 });

    const records = readStepRecords(tracePath);
    expect(records[2].actions).toEqual([]);
    expect(records[2].text).toContain("XSS vulnerability confirmed");
  });

  it("computes cumulative usage correctly", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });
    writer.recordStep(msgs.afterStep1, { inputTokens: 200, outputTokens: 80 });
    writer.recordStep(msgs.afterStep2, { inputTokens: 150, outputTokens: 60 });

    const records = readStepRecords(tracePath);

    expect(records[0].usage).toEqual({ inputTokens: 100, outputTokens: 50 });
    expect(records[0].cumulativeUsage).toEqual({
      inputTokens: 100,
      outputTokens: 50,
    });

    expect(records[1].usage).toEqual({ inputTokens: 200, outputTokens: 80 });
    expect(records[1].cumulativeUsage).toEqual({
      inputTokens: 300,
      outputTokens: 130,
    });

    expect(records[2].usage).toEqual({ inputTokens: 150, outputTokens: 60 });
    expect(records[2].cumulativeUsage).toEqual({
      inputTokens: 450,
      outputTokens: 190,
    });
  });

  it("tracks step duration and elapsed time", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });
    writer.recordStep(msgs.afterStep1, { inputTokens: 200, outputTokens: 80 });

    const records = readStepRecords(tracePath);
    // Can't assert exact values, but structure and non-negativity
    expect(records[0].stepDurationMs).toBeGreaterThanOrEqual(0);
    expect(records[0].elapsedMs).toBeGreaterThanOrEqual(0);
    expect(records[1].elapsedMs).toBeGreaterThanOrEqual(records[0].elapsedMs);
  });

  it("records summarized flag from markSummarized()", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });
    expect(readStepRecords(tracePath)[0].summarized).toBe(false);

    writer.markSummarized();

    // After summarization, the next step records against fresh messages
    const postSummaryMsg: ModelMessage[] = [
      {
        role: "assistant",
        content: [{ type: "text", text: "Continuing after summarization." }],
      },
    ];
    writer.recordStep(postSummaryMsg, { inputTokens: 80, outputTokens: 30 });

    const records = readStepRecords(tracePath);
    expect(records[1].summarized).toBe(true);
    expect(records[1].text).toBe("Continuing after summarization.");
    // stepIndex continues (does not reset)
    expect(records[1].stepIndex).toBe(1);
  });

  it("sets agentId correctly for orchestrator (null) and subagent", () => {
    const orchestratorPath = join(tmpDir, "orch.jsonl");
    const subagentPath = join(tmpDir, "sub.jsonl");
    const orchestrator = new StepTraceWriter({
      tracePath: orchestratorPath,
      agentId: null,
    });
    const subagent = new StepTraceWriter({
      tracePath: subagentPath,
      agentId: "pentest-agent-1",
    });

    const msgs: ModelMessage[] = [
      { role: "assistant", content: [{ type: "text", text: "hello" }] },
    ];

    orchestrator.recordStep(msgs, { inputTokens: 10, outputTokens: 5 });
    subagent.recordStep(msgs, { inputTokens: 10, outputTokens: 5 });

    const [orchRecord] = readStepRecords(orchestratorPath);
    const [subRecord] = readStepRecords(subagentPath);

    expect(orchRecord.agentId).toBeNull();
    expect(subRecord.agentId).toBe("pentest-agent-1");
  });

  it("caps outputPreview at 2000 chars", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });

    const longOutput = "x".repeat(5000);
    const msgs: ModelMessage[] = [
      {
        role: "assistant",
        content: [
          {
            type: "tool-call",
            toolCallId: "tc_setup",
            toolName: "setup",
            input: {},
          },
        ],
      },
    ];

    // Step 0 — just to advance past the "observations: null" step
    writer.recordStep(msgs, { inputTokens: 10, outputTokens: 5 });

    // Step 1 — with a huge tool result
    const msgs2: ModelMessage[] = [
      ...msgs,
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "tc_setup",
            toolName: "setup",
            output: { type: "text", value: longOutput },
          },
        ],
      },
      {
        role: "assistant",
        content: [{ type: "text", text: "done" }],
      },
    ];
    writer.recordStep(msgs2, { inputTokens: 10, outputTokens: 5 });

    const records = readStepRecords(tracePath);
    const obs = records[1].observations!;
    expect(obs[0].outputPreview.length).toBe(2000);
    expect(obs[0].outputLength).toBe(5000);
  });

  it("caps inputPreview at 1000 chars", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });

    const longInput = { data: "y".repeat(5000) };
    const msgs: ModelMessage[] = [
      {
        role: "assistant",
        content: [
          {
            type: "tool-call",
            toolCallId: "tc_big",
            toolName: "http_request",
            input: longInput,
          },
        ],
      },
    ];

    writer.recordStep(msgs, { inputTokens: 10, outputTokens: 5 });

    const [record] = readStepRecords(tracePath);
    expect(record.actions[0].inputPreview.length).toBe(1000);
    expect(record.actions[0].inputLength).toBeGreaterThan(1000);
  });

  it("produces valid JSON on every line", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });
    writer.recordStep(msgs.afterStep1, { inputTokens: 200, outputTokens: 80 });
    writer.recordStep(msgs.afterStep2, { inputTokens: 150, outputTokens: 60 });

    const lines = readFileSync(tracePath, "utf-8").trim().split("\n");
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  it("creates parent directories if they don't exist", () => {
    const nestedPath = join(tmpDir, "deep", "nested", "trace.jsonl");
    const writer = new StepTraceWriter({
      tracePath: nestedPath,
      agentId: null,
    });

    const msgs: ModelMessage[] = [
      { role: "assistant", content: [{ type: "text", text: "test" }] },
    ];
    writer.recordStep(msgs, { inputTokens: 10, outputTokens: 5 });

    const records = readStepRecords(nestedPath);
    expect(records).toHaveLength(1);
  });

  it("handles error output types correctly", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });

    // Step 0 with a tool call
    const msgs0: ModelMessage[] = [
      {
        role: "assistant",
        content: [
          {
            type: "tool-call",
            toolCallId: "tc_err",
            toolName: "execute_command",
            input: { command: "cat /nonexistent" },
          },
        ],
      },
    ];
    writer.recordStep(msgs0, { inputTokens: 10, outputTokens: 5 });

    // Step 1 with error-text result
    const msgs1: ModelMessage[] = [
      ...msgs0,
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "tc_err",
            toolName: "execute_command",
            output: {
              type: "error-text",
              value: "No such file or directory",
            },
          },
        ],
      },
      {
        role: "assistant",
        content: [{ type: "text", text: "File not found." }],
      },
    ];
    writer.recordStep(msgs1, { inputTokens: 20, outputTokens: 10 });

    const records = readStepRecords(tracePath);
    const obs = records[1].observations!;
    expect(obs[0].outputType).toBe("error-text");
    expect(obs[0].outputPreview).toContain("No such file or directory");
  });

  it("handles text-only assistant messages with no tool calls", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });

    const msgs: ModelMessage[] = [
      {
        role: "assistant",
        content: [{ type: "text", text: "I have completed the assessment." }],
      },
    ];

    writer.recordStep(msgs, { inputTokens: 50, outputTokens: 30 });

    const [record] = readStepRecords(tracePath);
    expect(record.text).toBe("I have completed the assessment.");
    expect(record.actions).toEqual([]);
    expect(record.reasoning).toBeNull();
  });

  it("handles string content in assistant messages", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });

    // Some model responses may use string content instead of parts
    const msgs: ModelMessage[] = [
      { role: "assistant", content: "Simple string response" },
    ];

    writer.recordStep(msgs, { inputTokens: 10, outputTokens: 5 });

    const [record] = readStepRecords(tracePath);
    expect(record.text).toBe("Simple string response");
  });

  it("records strategy-director usage without advancing operator steps", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: "fast-strike-1" });

    writer.recordAuxiliary("strategy_director", "Retire the stale path.", {
      inputTokens: 100,
      outputTokens: 20,
      cacheReadTokens: 10,
    });

    const [record] = readTraceRecords(tracePath) as AuxiliaryRecord[];
    expect(record.type).toBe("auxiliary");
    expect(record.stepIndex).toBe(0);
    expect(record.cumulativeUsage).toMatchObject({
      inputTokens: 100,
      outputTokens: 20,
      cacheReadTokens: 10,
    });
    expect(writer.currentStepIndex).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Checkpoint tests (PRD 2)
  // -------------------------------------------------------------------------

  it("appendCheckpoint writes a checkpoint record with type discriminator", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({
      tracePath,
      agentId: "pentest-agent-1",
    });

    writer.appendCheckpoint({
      targetState: {
        discoveredSurface: ["GET /api/users", "POST /api/login"],
        credentialsObtained: [],
        confirmedVulnerabilities: [],
      },
      actionsAttempted: [
        { description: "Probed /api/users for SQLi", outcome: "failure" },
      ],
      nextSteps: [
        {
          action: "Test XSS on /api/search",
          rationale: "Reflected input detected",
          priority: "high",
        },
      ],
      blockers: [],
      assessment: "Initial recon complete, no vulns found yet.",
    });

    const records = readTraceRecords(tracePath);
    expect(records).toHaveLength(1);

    const cp = records[0] as StateCheckpoint;
    expect(cp.type).toBe("checkpoint");
    expect(cp.stepIndex).toBe(0);
    expect(cp.agentId).toBe("pentest-agent-1");
    expect(cp.targetState.discoveredSurface).toHaveLength(2);
    expect(cp.actionsAttempted[0].outcome).toBe("failure");
    expect(cp.nextSteps[0].priority).toBe("high");
    expect(cp.assessment).toContain("Initial recon");
    expect(cp.timestamp).toBeTruthy();
  });

  it("checkpoint stepIndex matches the current in-flight step", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    // Complete step 0
    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });
    // Now during step 1 (tools executing), checkpoint is called
    writer.appendCheckpoint({
      targetState: {
        discoveredSurface: [],
        credentialsObtained: [],
        confirmedVulnerabilities: [],
      },
      actionsAttempted: [],
      nextSteps: [],
      blockers: [],
      assessment: "Mid-run checkpoint",
    });
    // Step 1 completes
    writer.recordStep(msgs.afterStep1, { inputTokens: 200, outputTokens: 80 });

    const records = readTraceRecords(tracePath);
    expect(records).toHaveLength(3);
    expect(records[0].type).toBe("step");
    expect((records[0] as StepRecord).stepIndex).toBe(0);
    expect(records[1].type).toBe("checkpoint");
    expect((records[1] as StateCheckpoint).stepIndex).toBe(1);
    expect(records[2].type).toBe("step");
    expect((records[2] as StepRecord).stepIndex).toBe(1);
  });

  it("checkpoints interleave with step records in trace.jsonl", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });
    writer.appendCheckpoint({
      targetState: {
        discoveredSurface: ["endpoint-a"],
        credentialsObtained: [],
        confirmedVulnerabilities: ["XSS on /search"],
      },
      actionsAttempted: [{ description: "Tested XSS", outcome: "success" }],
      nextSteps: [],
      blockers: [],
      assessment: "Found XSS",
    });
    writer.recordStep(msgs.afterStep1, { inputTokens: 200, outputTokens: 80 });

    const records = readTraceRecords(tracePath);
    expect(records.map((r) => r.type)).toEqual(["step", "checkpoint", "step"]);
  });

  it("checkpoint works with empty arrays (early in run)", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });

    writer.appendCheckpoint({
      targetState: {
        discoveredSurface: [],
        credentialsObtained: [],
        confirmedVulnerabilities: [],
      },
      actionsAttempted: [],
      nextSteps: [],
      blockers: [],
      assessment: "Just started.",
    });

    const records = readTraceRecords(tracePath);
    const cp = records[0] as StateCheckpoint;
    expect(cp.type).toBe("checkpoint");
    expect(cp.targetState.discoveredSurface).toEqual([]);
    expect(cp.actionsAttempted).toEqual([]);
  });

  it("currentStepIndex getter reflects the writer state", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    expect(writer.currentStepIndex).toBe(0);
    writer.recordStep(msgs.afterStep0, { inputTokens: 10, outputTokens: 5 });
    expect(writer.currentStepIndex).toBe(1);
    writer.recordStep(msgs.afterStep1, { inputTokens: 10, outputTokens: 5 });
    expect(writer.currentStepIndex).toBe(2);
  });

  // -------------------------------------------------------------------------
  // InitRecord tests
  // -------------------------------------------------------------------------

  it("writeInit emits an init record as the first line", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({
      tracePath,
      agentId: "pentest-agent-1",
    });

    writer.writeInit({
      model: "claude-sonnet-4-20250514",
      systemPrompt: "You are a pentest agent.",
      activeTools: ["execute_command", "http_request"],
      sessionId: "ses_test123",
      target: "https://example.com",
      objectives: ["Test for SQLi"],
    });

    const records = readTraceRecords(tracePath);
    expect(records).toHaveLength(1);

    const init = records[0] as InitRecord;
    expect(init.type).toBe("init");
    expect(init.agentId).toBe("pentest-agent-1");
    expect(init.model).toBe("claude-sonnet-4-20250514");
    expect(init.systemPromptHash).toHaveLength(12);
    expect(init.systemPromptHash).toMatch(/^[0-9a-f]{12}$/);
    expect(init.activeTools).toEqual(["execute_command", "http_request"]);
    expect(init.sessionId).toBe("ses_test123");
    expect(init.target).toBe("https://example.com");
    expect(init.objectives).toEqual(["Test for SQLi"]);
    expect(init.timestamp).toBeTruthy();
  });

  it("init record precedes step records in trace", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const writer = new StepTraceWriter({ tracePath, agentId: null });
    const msgs = buildMessages();

    writer.writeInit({
      model: "claude-sonnet-4-20250514",
      systemPrompt: "You are a pentest agent.",
      activeTools: ["execute_command"],
      sessionId: "ses_test",
    });
    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });

    const records = readTraceRecords(tracePath);
    expect(records.map((r) => r.type)).toEqual(["init", "step"]);
  });

  // -------------------------------------------------------------------------
  // onRecord callback tests
  // -------------------------------------------------------------------------

  it("eventBus receives trace-record events for every record written", () => {
    const tracePath = join(tmpDir, "trace.jsonl");
    const bus = new AgentEventBus();
    const received: TraceRecord[] = [];
    bus.on("trace-record", (e: { record: TraceRecord }) =>
      received.push(e.record),
    );

    const writer = new StepTraceWriter({
      tracePath,
      agentId: null,
      eventBus: bus,
    });
    const msgs = buildMessages();

    writer.writeInit({
      model: "test",
      systemPrompt: "test",
      activeTools: [],
      sessionId: "ses_test",
    });
    writer.recordStep(msgs.afterStep0, { inputTokens: 100, outputTokens: 50 });
    writer.appendCheckpoint({
      targetState: {
        discoveredSurface: [],
        credentialsObtained: [],
        confirmedVulnerabilities: [],
      },
      actionsAttempted: [],
      nextSteps: [],
      blockers: [],
      assessment: "test",
    });

    expect(received).toHaveLength(3);
    expect(received.map((r) => r.type)).toEqual(["init", "step", "checkpoint"]);
  });
});
