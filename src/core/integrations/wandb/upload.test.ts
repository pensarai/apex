import type { ModelMessage } from "ai";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  StepTraceWriter,
  type TraceRecord,
} from "../../agents/offSecAgent/trace";
import { AgentEventBus } from "../../eventBus";
import type { SessionInfo } from "../../session";
import { resolveConfig } from "./client";
import { createWandbUploader } from "./upload";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSession(overrides?: Partial<SessionInfo>): SessionInfo {
  return {
    id: "ses_test123",
    rootPath: "/tmp/test-session",
    findingsPath: "/tmp/test-session/findings",
    logsPath: "/tmp/test-session/logs",
    pocsPath: "/tmp/test-session/pocs",
    scratchpadPath: "/tmp/test-session/scratchpad",
    ...overrides,
  } as SessionInfo;
}

// ---------------------------------------------------------------------------
// Config detection
// ---------------------------------------------------------------------------

describe("resolveConfig", () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("returns unavailable when WANDB_API_KEY is not set", () => {
    delete process.env.WANDB_API_KEY;
    delete process.env.WANDB_ENTITY;
    const result = resolveConfig();
    expect(result.available).toBe(false);
  });

  it("returns unavailable when WANDB_ENTITY is not set", () => {
    process.env.WANDB_API_KEY = "test-key";
    delete process.env.WANDB_ENTITY;
    const result = resolveConfig();
    expect(result.available).toBe(false);
  });

  it("returns available with config when both env vars set", () => {
    process.env.WANDB_API_KEY = "test-key";
    process.env.WANDB_ENTITY = "test-entity";
    delete process.env.WANDB_PROJECT;
    const result = resolveConfig();
    expect(result.available).toBe(true);
    if (result.available) {
      expect(result.config.apiKey).toBe("test-key");
      expect(result.config.entity).toBe("test-entity");
      expect(result.config.project).toBe("apex-traces");
    }
  });

  it("uses WANDB_PROJECT env var when set", () => {
    process.env.WANDB_API_KEY = "key";
    process.env.WANDB_ENTITY = "entity";
    process.env.WANDB_PROJECT = "custom-project";
    const result = resolveConfig();
    expect(result.available).toBe(true);
    if (result.available) {
      expect(result.config.project).toBe("custom-project");
    }
  });

  it("uses overrides over env vars", () => {
    process.env.WANDB_API_KEY = "env-key";
    process.env.WANDB_ENTITY = "env-entity";
    const result = resolveConfig({
      apiKey: "override-key",
      entity: "override-entity",
      project: "override-project",
    });
    expect(result.available).toBe(true);
    if (result.available) {
      expect(result.config.apiKey).toBe("override-key");
      expect(result.config.entity).toBe("override-entity");
      expect(result.config.project).toBe("override-project");
    }
  });

  it("returns available when config provided via overrides only", () => {
    delete process.env.WANDB_API_KEY;
    delete process.env.WANDB_ENTITY;
    const result = resolveConfig({
      apiKey: "direct-key",
      entity: "direct-entity",
    });
    expect(result.available).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// createWandbUploader — graceful degradation
// ---------------------------------------------------------------------------

describe("createWandbUploader", () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("returns null when credentials are not configured", async () => {
    delete process.env.WANDB_API_KEY;
    delete process.env.WANDB_ENTITY;
    const result = await createWandbUploader(makeSession());
    expect(result).toBeNull();
  });

  it("returns null when only API key is set", async () => {
    process.env.WANDB_API_KEY = "key";
    delete process.env.WANDB_ENTITY;
    const result = await createWandbUploader(makeSession());
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// EventBus → uploader pipeline (integration test without real W&B)
// ---------------------------------------------------------------------------

describe("EventBus trace-record pipeline", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "wandb-pipeline-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("EventBus receives trace records from all agent types", () => {
    const bus = new AgentEventBus();
    const received: { record: TraceRecord; subagentId?: string }[] = [];
    bus.on("trace-record", (e) => received.push(e));

    // Orchestrator (no subagentId)
    const orchestratorWriter = new StepTraceWriter({
      tracePath: join(tmpDir, "orchestrator.jsonl"),
      agentId: null,
      eventBus: bus,
    });
    orchestratorWriter.writeInit({
      model: "test",
      systemPrompt: "orchestrator prompt",
      activeTools: ["run_attack_surface"],
      sessionId: "ses_1",
    });

    // Attack surface agent
    const asWriter = new StepTraceWriter({
      tracePath: join(tmpDir, "attack-surface.jsonl"),
      agentId: "attack-surface-agent",
      eventBus: bus,
    });
    asWriter.writeInit({
      model: "test",
      systemPrompt: "attack surface prompt",
      activeTools: ["execute_command", "document_endpoint"],
      sessionId: "ses_1",
    });

    // Pentest agent
    const pentestWriter = new StepTraceWriter({
      tracePath: join(tmpDir, "pentest-agent-1.jsonl"),
      agentId: "pentest-agent-1",
      eventBus: bus,
    });
    pentestWriter.writeInit({
      model: "test",
      systemPrompt: "pentest prompt",
      activeTools: ["execute_command", "http_request"],
      sessionId: "ses_1",
    });
    pentestWriter.recordStep(
      [
        {
          role: "assistant",
          content: [
            { type: "text", text: "Testing target." },
            {
              type: "tool-call",
              toolCallId: "tc1",
              toolName: "http_request",
              input: { url: "http://target" },
            },
          ],
        },
      ] as ModelMessage[],
      { inputTokens: 500, outputTokens: 200 },
    );

    // 3 init records + 1 step record = 4 total
    expect(received).toHaveLength(4);
    expect(received.map((r) => r.record.type)).toEqual([
      "init",
      "init",
      "init",
      "step",
    ]);

    // Verify subagentId tagging
    expect(received[0].subagentId).toBeUndefined(); // orchestrator
    expect(received[1].subagentId).toBe("attack-surface-agent");
    expect(received[2].subagentId).toBe("pentest-agent-1");
    expect(received[3].subagentId).toBe("pentest-agent-1");
  });

  it("trace records are written to disk even without EventBus", () => {
    const tracePath = join(tmpDir, "no-bus.jsonl");
    const writer = new StepTraceWriter({
      tracePath,
      agentId: null,
      // no eventBus
    });

    writer.writeInit({
      model: "test",
      systemPrompt: "test",
      activeTools: [],
      sessionId: "ses_1",
    });
    writer.recordStep(
      [
        {
          role: "assistant",
          content: [{ type: "text", text: "hello" }],
        },
      ] as ModelMessage[],
      { inputTokens: 10, outputTokens: 5 },
    );

    const lines = readFileSync(tracePath, "utf-8").trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).type).toBe("init");
    expect(JSON.parse(lines[1]).type).toBe("step");
  });

  it("EventBus listener can be removed without affecting file writes", () => {
    const bus = new AgentEventBus();
    const received: TraceRecord[] = [];
    const handler = (e: { record: TraceRecord }) => received.push(e.record);
    bus.on("trace-record", handler);

    const tracePath = join(tmpDir, "cleanup.jsonl");
    const writer = new StepTraceWriter({
      tracePath,
      agentId: null,
      eventBus: bus,
    });

    writer.writeInit({
      model: "test",
      systemPrompt: "test",
      activeTools: [],
      sessionId: "ses_1",
    });
    expect(received).toHaveLength(1);

    // Remove listener
    bus.off("trace-record", handler);

    writer.recordStep(
      [
        {
          role: "assistant",
          content: [{ type: "text", text: "after removal" }],
        },
      ] as ModelMessage[],
      { inputTokens: 10, outputTokens: 5 },
    );

    // EventBus stopped receiving, but file still written
    expect(received).toHaveLength(1);
    const lines = readFileSync(tracePath, "utf-8").trim().split("\n");
    expect(lines).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// InitRecord contract tests
// ---------------------------------------------------------------------------

describe("InitRecord hashing contract", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "init-hash-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("same system prompt produces same hash", () => {
    const prompt = "You are a pentest agent. Test for SQL injection.";

    const writer1 = new StepTraceWriter({
      tracePath: join(tmpDir, "a.jsonl"),
      agentId: null,
    });
    writer1.writeInit({
      model: "test",
      systemPrompt: prompt,
      activeTools: [],
      sessionId: "ses_1",
    });

    const writer2 = new StepTraceWriter({
      tracePath: join(tmpDir, "b.jsonl"),
      agentId: null,
    });
    writer2.writeInit({
      model: "test",
      systemPrompt: prompt,
      activeTools: [],
      sessionId: "ses_2",
    });

    const hash1 = (
      JSON.parse(readFileSync(join(tmpDir, "a.jsonl"), "utf-8")) as {
        systemPromptHash: string;
      }
    ).systemPromptHash;
    const hash2 = (
      JSON.parse(readFileSync(join(tmpDir, "b.jsonl"), "utf-8")) as {
        systemPromptHash: string;
      }
    ).systemPromptHash;

    expect(hash1).toBe(hash2);
  });

  it("different system prompts produce different hashes", () => {
    const writer1 = new StepTraceWriter({
      tracePath: join(tmpDir, "a.jsonl"),
      agentId: null,
    });
    writer1.writeInit({
      model: "test",
      systemPrompt: "Prompt version 1",
      activeTools: [],
      sessionId: "ses_1",
    });

    const writer2 = new StepTraceWriter({
      tracePath: join(tmpDir, "b.jsonl"),
      agentId: null,
    });
    writer2.writeInit({
      model: "test",
      systemPrompt: "Prompt version 2",
      activeTools: [],
      sessionId: "ses_1",
    });

    const hash1 = (
      JSON.parse(readFileSync(join(tmpDir, "a.jsonl"), "utf-8")) as {
        systemPromptHash: string;
      }
    ).systemPromptHash;
    const hash2 = (
      JSON.parse(readFileSync(join(tmpDir, "b.jsonl"), "utf-8")) as {
        systemPromptHash: string;
      }
    ).systemPromptHash;

    expect(hash1).not.toBe(hash2);
  });

  it("hash is always 12-char lowercase hex", () => {
    const prompts = [
      "",
      "short",
      "a".repeat(10000),
      "unicode: 你好世界 🔥",
      "special chars: \n\t\r\0",
    ];

    for (const prompt of prompts) {
      const tracePath = join(tmpDir, `hash-${Math.random()}.jsonl`);
      const writer = new StepTraceWriter({
        tracePath,
        agentId: null,
      });
      writer.writeInit({
        model: "test",
        systemPrompt: prompt,
        activeTools: [],
        sessionId: "ses_1",
      });

      const record = JSON.parse(readFileSync(tracePath, "utf-8")) as {
        systemPromptHash: string;
      };
      expect(record.systemPromptHash).toMatch(/^[0-9a-f]{12}$/);
    }
  });
});
