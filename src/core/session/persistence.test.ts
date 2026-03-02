import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdtempSync,
  rmSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
} from "fs";
import { join } from "path";
import { tmpdir } from "os";
import {
  mapToSavedMessage,
  parseSubagentFilename,
  convertMessagesToUI,
  saveSubagentData,
  loadSubagents,
  writeAgentManifest,
  readAgentManifest,
  type SavedMessage,
  type AgentManifestEntry,
  type SessionInfo,
} from "./persistence";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "persistence-test-"));
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function makeSession(overrides?: Partial<SessionInfo>): SessionInfo {
  return {
    id: "test-session",
    name: "test",
    version: "0.0.0",
    targets: ["http://localhost"],
    time: { created: Date.now(), updated: Date.now() },
    rootPath: tmpDir,
    logsPath: join(tmpDir, "logs"),
    findingsPath: join(tmpDir, "findings"),
    scratchpadPath: join(tmpDir, "scratchpad"),
    pocsPath: join(tmpDir, "pocs"),
    ...overrides,
  } as SessionInfo;
}

function makeMsg(role: string, content: unknown) {
  return { role, content };
}

function makeToolCallPart(toolName: string, args: Record<string, unknown>) {
  return {
    type: "tool-call",
    toolCallId: `tc-${toolName}`,
    toolName,
    args,
  };
}

function makeToolResultPart(toolName: string, result: unknown) {
  return {
    type: "tool-result",
    toolCallId: `tc-${toolName}`,
    toolName,
    result,
  };
}

// ---------------------------------------------------------------------------
// mapToSavedMessage
// ---------------------------------------------------------------------------

describe("mapToSavedMessage", () => {
  it("maps string content", () => {
    const result = mapToSavedMessage(makeMsg("assistant", "hello"));
    expect(result).toEqual({ role: "assistant", content: "hello" });
  });

  it("maps array content with text parts", () => {
    const result = mapToSavedMessage(
      makeMsg("assistant", [{ type: "text", text: "thinking..." }]),
    );
    expect(result.role).toBe("assistant");
    expect(Array.isArray(result.content)).toBe(true);
    const parts = result.content as Array<{ type: string; text?: string }>;
    expect(parts[0]).toEqual({ type: "text", text: "thinking..." });
  });

  it("maps tool-call: args → input", () => {
    const result = mapToSavedMessage(
      makeMsg("assistant", [
        makeToolCallPart("execute_command", { cmd: "ls" }),
      ]),
    );
    const parts = result.content as Array<{
      type: string;
      input?: Record<string, unknown>;
    }>;
    expect(parts[0].type).toBe("tool-call");
    expect(parts[0].input).toEqual({ cmd: "ls" });
  });

  it("maps tool-result: result → output", () => {
    const result = mapToSavedMessage(
      makeMsg("tool", [makeToolResultPart("execute_command", "output data")]),
    );
    const parts = result.content as Array<{ type: string; output?: unknown }>;
    expect(parts[0].type).toBe("tool-result");
    expect(parts[0].output).toBe("output data");
  });

  it("handles mixed content array", () => {
    const result = mapToSavedMessage(
      makeMsg("assistant", [
        { type: "text", text: "I'll run a command" },
        makeToolCallPart("execute_command", { cmd: "whoami" }),
      ]),
    );
    const parts = result.content as Array<{ type: string }>;
    expect(parts).toHaveLength(2);
    expect(parts[0].type).toBe("text");
    expect(parts[1].type).toBe("tool-call");
  });

  it("handles empty array content", () => {
    const result = mapToSavedMessage(makeMsg("assistant", []));
    expect(result.content).toEqual([]);
  });

  it("falls back to String() for non-string non-array content", () => {
    const result = mapToSavedMessage(makeMsg("assistant", 42));
    expect(result.content).toBe("42");
  });

  it("falls back to String() for null content", () => {
    const result = mapToSavedMessage(makeMsg("assistant", null));
    expect(result.content).toBe("null");
  });
});

// ---------------------------------------------------------------------------
// parseSubagentFilename
// ---------------------------------------------------------------------------

describe("parseSubagentFilename", () => {
  it("parses attack-surface-agent filename", () => {
    const result = parseSubagentFilename(
      "attack-surface-agent-2025-12-05T10-30-00-000Z.json",
    );
    expect(result.agentType).toBe("attack-surface");
    expect(result.name).toBe("Attack Surface Discovery");
  });

  it("parses pentest-agent-{N} filename", () => {
    const result = parseSubagentFilename(
      "pentest-agent-3-2025-12-05T10-30-00-000Z.json",
    );
    expect(result.agentType).toBe("pentest");
    expect(result.name).toBe("Pentest Agent 3");
  });

  it("parses vuln-test filename (backwards compat)", () => {
    const result = parseSubagentFilename(
      "vuln-test-sqli-http---localhost-2025-12-05T10-30-00-000Z.json",
    );
    expect(result.agentType).toBe("pentest");
    expect(result.name).toMatch(/Test/);
  });

  it("parses orchestrator filename", () => {
    const result = parseSubagentFilename(
      "orchestrator-2025-12-05T10-30-00-000Z.json",
    );
    expect(result.agentType).toBe("pentest");
    expect(result.name).toBe("Orchestrator Summary");
  });

  it("uses fallback for unknown prefix", () => {
    const result = parseSubagentFilename(
      "custom-agent-2025-12-05T10-30-00-000Z.json",
    );
    expect(result.agentType).toBe("pentest");
  });
});

// ---------------------------------------------------------------------------
// convertMessagesToUI
// ---------------------------------------------------------------------------

describe("convertMessagesToUI", () => {
  const baseTime = new Date("2025-01-01T00:00:00Z");

  it("converts assistant text message", () => {
    const messages: SavedMessage[] = [{ role: "assistant", content: "Hello" }];
    const result = convertMessagesToUI(messages, baseTime);
    expect(result).toHaveLength(1);
    expect(result[0].role).toBe("assistant");
    expect(result[0].content).toBe("Hello");
  });

  it("converts tool-call with result pairing", () => {
    const messages: SavedMessage[] = [
      {
        role: "assistant",
        content: [
          {
            type: "tool-call",
            toolCallId: "tc-1",
            toolName: "execute_command",
            input: { cmd: "ls" },
          },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "tc-1",
            toolName: "execute_command",
            output: "file1.txt\nfile2.txt",
          },
        ],
      },
    ];
    const result = convertMessagesToUI(messages, baseTime);
    const toolMsg = result.find((m) => m.role === "tool");
    expect(toolMsg).toBeDefined();
    expect(toolMsg!.toolName).toBe("execute_command");
    expect(toolMsg!.result).toBe("file1.txt\nfile2.txt");
    expect(toolMsg!.status).toBe("completed");
  });

  it("returns empty array for empty messages", () => {
    expect(convertMessagesToUI([], baseTime)).toEqual([]);
  });

  it("increments timestamps correctly", () => {
    const messages: SavedMessage[] = [
      { role: "assistant", content: "First" },
      { role: "assistant", content: "Second" },
      { role: "assistant", content: "Third" },
    ];
    const result = convertMessagesToUI(messages, baseTime);
    expect(result[0].createdAt.getTime()).toBe(baseTime.getTime());
    expect(result[1].createdAt.getTime()).toBe(baseTime.getTime() + 1000);
    expect(result[2].createdAt.getTime()).toBe(baseTime.getTime() + 2000);
  });
});

// ---------------------------------------------------------------------------
// saveSubagentData + loadSubagents roundtrip
// ---------------------------------------------------------------------------

describe("saveSubagentData + loadSubagents roundtrip", () => {
  it("saves and loads a single agent", () => {
    const session = makeSession();
    saveSubagentData(session, {
      agentName: "pentest-agent-1",
      target: "http://localhost:8080",
      objective: "Test SQL injection",
      status: "completed",
      findingsCount: 2,
      messages: [makeMsg("assistant", "Testing SQL injection...")],
    });

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(1);
    expect(loaded[0].type).toBe("pentest");
    expect(loaded[0].name).toBe("Pentest Agent 1");
    expect(loaded[0].target).toBe("http://localhost:8080");
    expect(loaded[0].status).toBe("completed");
    expect(loaded[0].messages.length).toBeGreaterThan(0);
  });

  it("saves and loads multiple agents", () => {
    const session = makeSession();
    saveSubagentData(session, {
      agentName: "pentest-agent-1",
      target: "http://localhost:8080/api",
      status: "completed",
      messages: [makeMsg("assistant", "Agent 1")],
    });
    saveSubagentData(session, {
      agentName: "pentest-agent-2",
      target: "http://localhost:8080/admin",
      status: "completed",
      messages: [makeMsg("assistant", "Agent 2")],
    });

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(2);
  });

  it("saves attack-surface + pentest agents with correct types", () => {
    const session = makeSession();
    saveSubagentData(session, {
      agentName: "attack-surface-agent",
      target: "http://localhost:8080",
      status: "completed",
      messages: [makeMsg("assistant", "Discovered 3 endpoints")],
    });
    saveSubagentData(session, {
      agentName: "pentest-agent-1",
      target: "http://localhost:8080/api",
      status: "completed",
      messages: [makeMsg("assistant", "Testing...")],
    });

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(2);
    const types = loaded.map((s) => s.type);
    expect(types).toContain("attack-surface");
    expect(types).toContain("pentest");
  });

  it("handles empty messages", () => {
    const session = makeSession();
    saveSubagentData(session, {
      agentName: "pentest-agent-1",
      target: "http://localhost:8080",
      status: "completed",
      messages: [],
    });

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(1);
    expect(loaded[0].messages).toHaveLength(0);
  });

  it("preserves failed status", () => {
    const session = makeSession();
    saveSubagentData(session, {
      agentName: "pentest-agent-1",
      target: "http://localhost:8080",
      status: "failed",
      error: "Connection refused",
      messages: [makeMsg("assistant", "Attempting connection...")],
    });

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(1);
    expect(loaded[0].status).toBe("failed");
  });

  it("passes findingsCount through correctly", () => {
    const session = makeSession();
    saveSubagentData(session, {
      agentName: "pentest-agent-1",
      target: "http://localhost:8080",
      status: "completed",
      findingsCount: 5,
      messages: [],
    });

    // Verify the raw JSON has the correct findingsCount
    const files = require("fs").readdirSync(join(tmpDir, "subagents"));
    const data = JSON.parse(
      readFileSync(join(tmpDir, "subagents", files[0]), "utf-8"),
    );
    expect(data.findingsCount).toBe(5);
  });

  it("returns empty array when subagents directory does not exist", () => {
    const loaded = loadSubagents(tmpDir);
    expect(loaded).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Manifest roundtrip
// ---------------------------------------------------------------------------

describe("manifest roundtrip", () => {
  it("writes and reads manifest entries", () => {
    const session = makeSession();
    const entries: AgentManifestEntry[] = [
      {
        id: "pentest-agent-1",
        name: "Pentest Agent 1",
        target: "http://localhost:8080",
        vulnerabilityClass: "SQL Injection",
        objective: "Test for SQL injection",
        status: "running",
        spawnedAt: new Date().toISOString(),
      },
    ];

    writeAgentManifest(session, entries);
    const loaded = readAgentManifest(session);
    expect(loaded).toHaveLength(1);
    expect(loaded[0].id).toBe("pentest-agent-1");
    expect(loaded[0].status).toBe("running");
  });

  it("returns empty array for nonexistent manifest", () => {
    const session = makeSession();
    const loaded = readAgentManifest(session);
    expect(loaded).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// loadSubagents manifest merge
// ---------------------------------------------------------------------------

describe("loadSubagents manifest merge", () => {
  it("marks completed file as paused when manifest says running", () => {
    const session = makeSession();

    // Save a completed agent
    saveSubagentData(session, {
      agentName: "pentest-agent-1",
      target: "http://localhost:8080",
      status: "completed",
      messages: [makeMsg("assistant", "Done")],
    });

    // Write manifest saying it's still running
    writeAgentManifest(session, [
      {
        id: "pentest-agent-1",
        name: "Pentest Agent 1",
        target: "http://localhost:8080",
        vulnerabilityClass: "SQL Injection",
        objective: "Test SQL injection",
        status: "running",
        spawnedAt: new Date().toISOString(),
      },
    ]);

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(1);
    expect(loaded[0].status).toBe("paused");
    expect(loaded[0].resumeInfo).toBeDefined();
    expect(loaded[0].resumeInfo!.vulnerabilityClass).toBe("SQL Injection");
  });

  it("leaves completed file as-is when manifest also says completed", () => {
    const session = makeSession();

    saveSubagentData(session, {
      agentName: "pentest-agent-1",
      target: "http://localhost:8080",
      status: "completed",
      messages: [makeMsg("assistant", "Done")],
    });

    writeAgentManifest(session, [
      {
        id: "pentest-agent-1",
        name: "Pentest Agent 1",
        target: "http://localhost:8080",
        vulnerabilityClass: "SQL Injection",
        objective: "Test SQL injection",
        status: "completed",
        spawnedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
      },
    ]);

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(1);
    expect(loaded[0].status).toBe("completed");
  });

  it("creates paused stub when manifest entry has no matching file", () => {
    const session = makeSession();

    // No files saved, but manifest says agent was running
    writeAgentManifest(session, [
      {
        id: "pentest-agent-1",
        name: "Pentest Agent 1",
        target: "http://localhost:8080",
        vulnerabilityClass: "XSS",
        objective: "Test for XSS",
        status: "running",
        spawnedAt: "2025-01-01T00:00:00.000Z",
      },
    ]);

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(1);
    expect(loaded[0].id).toBe("pentest-agent-1");
    expect(loaded[0].status).toBe("paused");
    expect(loaded[0].messages).toHaveLength(0);
    expect(loaded[0].resumeInfo!.target).toBe("http://localhost:8080");
  });

  it("does not duplicate when manifest matches existing file", () => {
    const session = makeSession();

    saveSubagentData(session, {
      agentName: "pentest-agent-1",
      target: "http://localhost:8080",
      status: "completed",
      messages: [],
    });

    saveSubagentData(session, {
      agentName: "pentest-agent-2",
      target: "http://localhost:8080/admin",
      status: "completed",
      messages: [],
    });

    writeAgentManifest(session, [
      {
        id: "pentest-agent-1",
        name: "Pentest Agent 1",
        target: "http://localhost:8080",
        vulnerabilityClass: "SQLi",
        objective: "Test SQLi",
        status: "running",
        spawnedAt: new Date().toISOString(),
      },
      {
        id: "pentest-agent-2",
        name: "Pentest Agent 2",
        target: "http://localhost:8080/admin",
        vulnerabilityClass: "XSS",
        objective: "Test XSS",
        status: "completed",
        spawnedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
      },
    ]);

    const loaded = loadSubagents(tmpDir);
    // Should be exactly 2 — one paused (agent-1), one completed (agent-2)
    expect(loaded).toHaveLength(2);
    const agent1 = loaded.find((s) => s.name === "Pentest Agent 1");
    const agent2 = loaded.find((s) => s.name === "Pentest Agent 2");
    expect(agent1!.status).toBe("paused");
    expect(agent2!.status).toBe("completed");
  });

  it("skips orchestrator files", () => {
    // Manually write an orchestrator file
    const subagentsDir = join(tmpDir, "subagents");
    mkdirSync(subagentsDir, { recursive: true });
    writeFileSync(
      join(subagentsDir, "orchestrator-2025-12-05T10-30-00-000Z.json"),
      JSON.stringify({
        agentName: "orchestrator",
        timestamp: "2025-12-05T10:30:00.000Z",
        messages: [],
      }),
    );

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Operator state modelMessages persistence
// ---------------------------------------------------------------------------

describe("operator state modelMessages persistence", () => {
  // These tests verify the roundtrip of modelMessages through the
  // operator-state.json file, which is what saveOperatorState/loadOperatorState
  // do under the hood (JSON.stringify → writeFile → readFile → JSON.parse).

  const STATE_FILE = "operator-state.json";

  function writeOperatorState(rootPath: string, state: Record<string, unknown>) {
    writeFileSync(join(rootPath, STATE_FILE), JSON.stringify(state, null, 2));
  }

  function readOperatorState(rootPath: string): Record<string, unknown> | null {
    const statePath = join(rootPath, STATE_FILE);
    if (!existsSync(statePath)) return null;
    return JSON.parse(readFileSync(statePath, "utf-8"));
  }

  it("roundtrips modelMessages through save and load", () => {
    const modelMessages = [
      { role: "user", content: "what tools do you have?" },
      {
        role: "assistant",
        content: [
          { type: "text", text: "I have several tools available." },
          {
            type: "tool-call",
            toolCallId: "tc-1",
            toolName: "execute_command",
            args: { cmd: "ls" },
          },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "tc-1",
            toolName: "execute_command",
            result: "file1.txt\nfile2.txt",
          },
        ],
      },
      { role: "assistant", content: "I found two files." },
    ];

    writeOperatorState(tmpDir, {
      mode: "manual",
      autoApproveTier: 2,
      currentStage: "recon",
      messages: [],
      modelMessages,
    });

    const loaded = readOperatorState(tmpDir);
    expect(loaded).not.toBeNull();
    expect(loaded!.modelMessages).toEqual(modelMessages);
  });

  it("handles missing modelMessages (backward compat)", () => {
    // Saved state from before modelMessages was added
    writeOperatorState(tmpDir, {
      mode: "manual",
      autoApproveTier: 2,
      currentStage: "recon",
      messages: [],
    });

    const loaded = readOperatorState(tmpDir);
    expect(loaded).not.toBeNull();
    expect(loaded!.modelMessages).toBeUndefined();

    // Simulates the resume logic: default to empty array when missing
    const restored = Array.isArray(loaded!.modelMessages)
      ? loaded!.modelMessages
      : [];
    expect(restored).toEqual([]);
  });

  it("preserves empty modelMessages array", () => {
    writeOperatorState(tmpDir, {
      mode: "manual",
      autoApproveTier: 2,
      currentStage: "recon",
      messages: [],
      modelMessages: [],
    });

    const loaded = readOperatorState(tmpDir);
    expect(loaded).not.toBeNull();
    expect(loaded!.modelMessages).toEqual([]);
  });

  it("preserves display messages alongside model messages", () => {
    const displayMessages = [
      { role: "user", content: "hello", createdAt: new Date().toISOString() },
      {
        role: "assistant",
        content: "Hi there!",
        createdAt: new Date().toISOString(),
      },
    ];
    const modelMessages = [
      { role: "user", content: "hello" },
      { role: "assistant", content: "Hi there!" },
    ];

    writeOperatorState(tmpDir, {
      mode: "auto",
      autoApproveTier: 3,
      currentStage: "foothold",
      messages: displayMessages,
      modelMessages,
    });

    const loaded = readOperatorState(tmpDir);
    expect(loaded!.messages).toEqual(displayMessages);
    expect(loaded!.modelMessages).toEqual(modelMessages);
  });
});
