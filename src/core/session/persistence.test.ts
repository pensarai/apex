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
import type { ModelMessage } from "ai";
import {
  saveSubagentData,
  loadSubagents,
  writeAgentManifest,
  readAgentManifest,
  convertModelMessagesToUI,
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

function makeMsg(role: string, content: unknown): ModelMessage {
  return { role, content } as ModelMessage;
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
// saveSubagentData + loadSubagents roundtrip
// ---------------------------------------------------------------------------

describe("saveSubagentData + loadSubagents roundtrip", () => {
  it("roundtrips tool-call args→input and tool-result result→output", () => {
    const session = makeSession();
    saveSubagentData(session, {
      agentName: "pentest-agent-1",
      target: "http://localhost:8080",
      status: "completed",
      messages: [
        makeMsg("assistant", [
          { type: "text", text: "I'll run a command" },
          makeToolCallPart("execute_command", { cmd: "ls" }),
        ]),
        makeMsg("tool", [
          makeToolResultPart("execute_command", "file1.txt\nfile2.txt"),
        ]),
      ],
    });

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(1);

    // Verify tool-call was paired with its result in UI messages
    const toolMsg = loaded[0].messages.find((m) => m.role === "tool");
    expect(toolMsg).toBeDefined();
    expect(toolMsg!.toolName).toBe("execute_command");
    expect(toolMsg!.args).toEqual({ cmd: "ls" });
    expect(toolMsg!.result).toBe("file1.txt\nfile2.txt");
    expect(toolMsg!.status).toBe("completed");

    // Verify text part also came through
    const textMsg = loaded[0].messages.find(
      (m) => m.role === "assistant" && m.content.includes("run a command"),
    );
    expect(textMsg).toBeDefined();
  });

  it("roundtrips attack-surface and pentest agent types", () => {
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

    // Verify names are parsed correctly from filenames
    const attackSurface = loaded.find((s) => s.type === "attack-surface");
    expect(attackSurface!.name).toBe("Attack Surface Discovery");
    const pentest = loaded.find((s) => s.type === "pentest");
    expect(pentest!.name).toBe("Pentest Agent 1");
  });

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
// Operator state persistence (single messages field)
// ---------------------------------------------------------------------------

describe("operator state persistence", () => {
  // These tests verify the roundtrip of model messages through the
  // operator-state.json file. The persisted state stores a single `messages`
  // field containing raw AI SDK model messages. Display messages are derived
  // on resume via convertModelMessagesToUI.

  const STATE_FILE = "operator-state.json";

  function writeOperatorState(
    rootPath: string,
    state: Record<string, unknown>,
  ) {
    writeFileSync(join(rootPath, STATE_FILE), JSON.stringify(state, null, 2));
  }

  function readOperatorState(rootPath: string): Record<string, unknown> | null {
    const statePath = join(rootPath, STATE_FILE);
    if (!existsSync(statePath)) return null;
    return JSON.parse(readFileSync(statePath, "utf-8"));
  }

  it("roundtrips model messages through save and load", () => {
    const messages = [
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
      messages,
    });

    const loaded = readOperatorState(tmpDir);
    expect(loaded).not.toBeNull();
    expect(loaded!.messages).toEqual(messages);
  });

  it("handles empty messages array", () => {
    writeOperatorState(tmpDir, {
      mode: "manual",
      autoApproveTier: 2,
      currentStage: "recon",
      messages: [],
    });

    const loaded = readOperatorState(tmpDir);
    expect(loaded).not.toBeNull();
    expect(loaded!.messages).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// convertModelMessagesToUI
// ---------------------------------------------------------------------------

describe("convertModelMessagesToUI", () => {
  it("converts model messages to UI format with tool pairing", () => {
    const modelMessages: ModelMessage[] = [
      makeMsg("user", "run a scan"),
      makeMsg("assistant", [
        { type: "text", text: "I'll run a command" },
        {
          type: "tool-call",
          toolCallId: "tc-1",
          toolName: "execute_command",
          args: { cmd: "nmap localhost" },
        },
      ]),
      makeMsg("tool", [
        {
          type: "tool-result",
          toolCallId: "tc-1",
          toolName: "execute_command",
          result: "PORT 80/tcp open",
        },
      ]),
      makeMsg("assistant", "Found port 80 open."),
    ];

    const uiMsgs = convertModelMessagesToUI(modelMessages);

    // Should have: user msg, assistant text, tool call, assistant text
    expect(uiMsgs.length).toBe(4);

    // User message
    expect(uiMsgs[0].role).toBe("user");
    expect(uiMsgs[0].content).toBe("run a scan");

    // Assistant text
    expect(uiMsgs[1].role).toBe("assistant");
    expect(uiMsgs[1].content).toBe("I'll run a command");

    // Tool call with paired result
    expect(uiMsgs[2].role).toBe("tool");
    expect(uiMsgs[2].toolName).toBe("execute_command");
    expect(uiMsgs[2].args).toEqual({ cmd: "nmap localhost" });
    expect(uiMsgs[2].result).toBe("PORT 80/tcp open");
    expect(uiMsgs[2].status).toBe("completed");

    // Final assistant text
    expect(uiMsgs[3].role).toBe("assistant");
    expect(uiMsgs[3].content).toBe("Found port 80 open.");
  });

  it("returns empty array for empty input", () => {
    const uiMsgs = convertModelMessagesToUI([]);
    expect(uiMsgs).toEqual([]);
  });
});
