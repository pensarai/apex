import type { ModelMessage } from "ai";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getResumeMessages, normalizeMessages } from "./index";
import {
  type AgentManifestEntry,
  convertModelMessagesToUI,
  loadSubagents,
  readAgentManifest,
  type SessionInfo,
  saveSubagentData,
  writeAgentManifest,
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

function makeToolCallPart(toolName: string, input: Record<string, unknown>) {
  return {
    type: "tool-call",
    toolCallId: `tc-${toolName}`,
    toolName,
    input,
  };
}

function makeToolResultPart(toolName: string, output: unknown) {
  return {
    type: "tool-result",
    toolCallId: `tc-${toolName}`,
    toolName,
    output,
  };
}

// ---------------------------------------------------------------------------
// saveSubagentData + loadSubagents roundtrip
// ---------------------------------------------------------------------------

describe("saveSubagentData + loadSubagents roundtrip", () => {
  it("roundtrips tool-call and tool-result content parts", () => {
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
    expect(toolMsg?.toolName).toBe("execute_command");
    expect(toolMsg?.args).toEqual({ cmd: "ls" });
    expect(toolMsg?.result).toBe("file1.txt\nfile2.txt");
    expect(toolMsg?.status).toBe("completed");

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
    expect(attackSurface?.name).toBe("Attack Surface Discovery");
    const pentest = loaded.find((s) => s.type === "pentest");
    expect(pentest?.name).toBe("Pentest Agent 1");
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
    const files = require("node:fs").readdirSync(join(tmpDir, "subagents"));
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
    expect(loaded[0].resumeInfo?.vulnerabilityClass).toBe("SQL Injection");
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
    expect(loaded[0].resumeInfo?.target).toBe("http://localhost:8080");
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
    expect(agent1?.status).toBe("paused");
    expect(agent2?.status).toBe("completed");
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
// Directory-only subagent discovery
// ---------------------------------------------------------------------------

describe("loadSubagents directory-only discovery", () => {
  it("discovers threat-model agents from messages.json directories", () => {
    const subagentsDir = join(tmpDir, "subagents");
    const tmDir = join(subagentsDir, "threat-model-myapp-_api_users");
    mkdirSync(tmDir, { recursive: true });
    writeFileSync(
      join(tmDir, "messages.json"),
      JSON.stringify([
        { role: "user", content: "Analyze endpoint /api/users" },
        {
          role: "assistant",
          content: [{ type: "text", text: "Analyzing..." }],
        },
      ]),
    );

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(1);
    expect(loaded[0].id).toBe("threat-model-myapp-_api_users");
    expect(loaded[0].type).toBe("pentest");
    expect(loaded[0].name).toContain("Threat Model");
    expect(loaded[0].status).toBe("completed");
    expect(loaded[0].messages.length).toBeGreaterThan(0);
  });

  it("discovers whitebox discovery agents from messages.json directories", () => {
    const subagentsDir = join(tmpDir, "subagents");
    for (const dirName of [
      "whitebox-apps-discovery",
      "pages-myapp",
      "apiEndpoints-myapp",
    ]) {
      const dir = join(subagentsDir, dirName);
      mkdirSync(dir, { recursive: true });
      writeFileSync(
        join(dir, "messages.json"),
        JSON.stringify([
          { role: "user", content: `Discover ${dirName}` },
          {
            role: "assistant",
            content: [{ type: "text", text: "Found endpoints" }],
          },
        ]),
      );
    }

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(3);
    const ids = loaded.map((s) => s.id);
    expect(ids).toContain("whitebox-apps-discovery");
    expect(ids).toContain("pages-myapp");
    expect(ids).toContain("apiEndpoints-myapp");
  });

  it("does not duplicate agents that have both .json snapshot and directory", () => {
    const session = makeSession();
    saveSubagentData(session, {
      agentName: "pentest-agent-1",
      target: "http://localhost:8080",
      status: "completed",
      messages: [],
    });

    // Also create the messages.json directory (this happens at runtime)
    const msgDir = join(tmpDir, "subagents", "pentest-agent-1");
    mkdirSync(msgDir, { recursive: true });
    writeFileSync(
      join(msgDir, "messages.json"),
      JSON.stringify([
        { role: "user", content: "Test" },
        { role: "assistant", content: [{ type: "text", text: "Testing" }] },
      ]),
    );

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(1);
  });

  it("skips -tasks and -plan directories", () => {
    const subagentsDir = join(tmpDir, "subagents");
    for (const dirName of ["pentest-agent-1-tasks", "pentest-agent-1-plan"]) {
      const dir = join(subagentsDir, dirName);
      mkdirSync(dir, { recursive: true });
      writeFileSync(
        join(dir, "messages.json"),
        JSON.stringify([{ role: "user", content: "test" }]),
      );
    }

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(0);
  });

  it("skips directories without messages.json", () => {
    const subagentsDir = join(tmpDir, "subagents");
    const dir = join(subagentsDir, "threat-model-empty");
    mkdirSync(dir, { recursive: true });

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(0);
  });

  it("skips directories with empty messages array", () => {
    const subagentsDir = join(tmpDir, "subagents");
    const dir = join(subagentsDir, "threat-model-empty");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "messages.json"), JSON.stringify([]));

    const loaded = loadSubagents(tmpDir);
    expect(loaded).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Operator state persistence (single messages field)
// ---------------------------------------------------------------------------

describe("operator state persistence", () => {
  // These tests verify the roundtrip of model messages through the
  // messages.json file. The persisted state stores a single `messages`
  // field containing raw AI SDK model messages. Display messages are derived
  // on resume via convertModelMessagesToUI.

  const STATE_FILE = "messages.json";

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
    expect(loaded?.messages).toEqual(messages);
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
    expect(loaded?.messages).toEqual([]);
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
          input: { cmd: "nmap localhost" },
        },
      ]),
      makeMsg("tool", [
        {
          type: "tool-result",
          toolCallId: "tc-1",
          toolName: "execute_command",
          output: "PORT 80/tcp open",
        },
      ]),
      makeMsg("assistant", "Found port 80 open."),
    ];

    const uiMsgs = convertModelMessagesToUI(modelMessages);

    expect(uiMsgs.length).toBe(4);

    expect(uiMsgs[0].role).toBe("user");
    expect(uiMsgs[0].content).toBe("run a scan");

    expect(uiMsgs[1].role).toBe("assistant");
    expect(uiMsgs[1].content).toBe("I'll run a command");

    expect(uiMsgs[2].role).toBe("tool");
    expect(uiMsgs[2].toolName).toBe("execute_command");
    expect(uiMsgs[2].args).toEqual({ cmd: "nmap localhost" });
    expect(uiMsgs[2].result).toBe("PORT 80/tcp open");
    expect(uiMsgs[2].status).toBe("completed");

    expect(uiMsgs[3].role).toBe("assistant");
    expect(uiMsgs[3].content).toBe("Found port 80 open.");
  });

  it("unwraps AI SDK json-wrapped tool output (operator messages.json resume)", () => {
    const modelMessages: ModelMessage[] = [
      makeMsg("user", "read it"),
      makeMsg("assistant", [
        { type: "text", text: "Reading" },
        {
          type: "tool-call",
          toolCallId: "tc-read",
          toolName: "read_file",
          input: { path: "README.md", toolCallDescription: "read README.md" },
        },
      ]),
      makeMsg("tool", [
        {
          type: "tool-result",
          toolCallId: "tc-read",
          toolName: "read_file",
          output: {
            type: "json",
            value: {
              success: true,
              error: "",
              content: "     1|hello",
              path: "README.md",
              totalLines: 80,
            },
          },
        },
      ]),
    ];

    const uiMsgs = convertModelMessagesToUI(modelMessages);
    const toolMsg = uiMsgs.find((m) => m.role === "tool");
    expect(toolMsg?.result).toEqual({
      success: true,
      error: "",
      content: "     1|hello",
      path: "README.md",
      totalLines: 80,
    });
  });

  it("unwraps AI SDK text-wrapped tool output without JSON-parsing", () => {
    const modelMessages: ModelMessage[] = [
      makeMsg("assistant", [
        makeToolCallPart("execute_command", { cmd: "curl http://api/health" }),
      ]),
      makeMsg("tool", [
        makeToolResultPart("execute_command", {
          type: "text",
          value: '{"status":"ok"}',
        }),
      ]),
    ];

    const uiMsgs = convertModelMessagesToUI(modelMessages);
    const toolMsg = uiMsgs.find((m) => m.role === "tool");
    // Should stay a string, not get JSON.parsed into an object
    expect(toolMsg?.result).toBe('{"status":"ok"}');
  });

  it("unwraps AI SDK error-json-wrapped tool output", () => {
    const modelMessages: ModelMessage[] = [
      makeMsg("assistant", [
        makeToolCallPart("execute_command", { cmd: "fail" }),
      ]),
      makeMsg("tool", [
        makeToolResultPart("execute_command", {
          type: "error-json",
          value: { error: "Connection refused", code: "ECONNREFUSED" },
        }),
      ]),
    ];

    const uiMsgs = convertModelMessagesToUI(modelMessages);
    const toolMsg = uiMsgs.find((m) => m.role === "tool");
    expect(toolMsg?.result).toEqual({
      error: "Connection refused",
      code: "ECONNREFUSED",
    });
  });

  it("unwraps AI SDK error-text-wrapped tool output", () => {
    const modelMessages: ModelMessage[] = [
      makeMsg("assistant", [
        makeToolCallPart("read_file", { path: "/nonexistent" }),
      ]),
      makeMsg("tool", [
        makeToolResultPart("read_file", {
          type: "error-text",
          value: "ENOENT: no such file or directory",
        }),
      ]),
    ];

    const uiMsgs = convertModelMessagesToUI(modelMessages);
    const toolMsg = uiMsgs.find((m) => m.role === "tool");
    expect(toolMsg?.result).toBe("ENOENT: no such file or directory");
  });

  it("unwraps AI SDK execution-denied tool output", () => {
    const modelMessages: ModelMessage[] = [
      makeMsg("assistant", [
        makeToolCallPart("execute_command", { cmd: "rm -rf /" }),
      ]),
      makeMsg("tool", [
        makeToolResultPart("execute_command", {
          type: "execution-denied",
          reason: "Command blocked by sandbox",
        }),
      ]),
    ];

    const uiMsgs = convertModelMessagesToUI(modelMessages);
    const toolMsg = uiMsgs.find((m) => m.role === "tool");
    expect(toolMsg?.result).toBe("Command blocked by sandbox");
  });

  it("unwraps execution-denied with no reason", () => {
    const modelMessages: ModelMessage[] = [
      makeMsg("assistant", [
        makeToolCallPart("execute_command", { cmd: "bad" }),
      ]),
      makeMsg("tool", [
        makeToolResultPart("execute_command", {
          type: "execution-denied",
        }),
      ]),
    ];

    const uiMsgs = convertModelMessagesToUI(modelMessages);
    const toolMsg = uiMsgs.find((m) => m.role === "tool");
    expect(toolMsg?.result).toBe("Tool execution denied");
  });

  it("returns empty array for empty input", () => {
    const uiMsgs = convertModelMessagesToUI([]);
    expect(uiMsgs).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// getResumeMessages
// ---------------------------------------------------------------------------

describe("getResumeMessages", () => {
  it("returns all messages when under the limit", () => {
    const msgs: ModelMessage[] = [
      makeMsg("user", "hello"),
      makeMsg("assistant", "hi"),
      makeMsg("user", "scan"),
      makeMsg("assistant", "scanning..."),
    ];
    expect(getResumeMessages(msgs, 10)).toEqual(msgs);
  });

  it("returns all messages when exactly at the limit", () => {
    const msgs: ModelMessage[] = Array.from({ length: 5 }, (_, i) =>
      makeMsg(i % 2 === 0 ? "user" : "assistant", `msg-${i}`),
    );
    expect(getResumeMessages(msgs, 5)).toEqual(msgs);
  });

  it("trims to the limit and cuts at a user message boundary", () => {
    // 10 messages: u a u a u a u a u a
    const msgs: ModelMessage[] = Array.from({ length: 10 }, (_, i) =>
      makeMsg(i % 2 === 0 ? "user" : "assistant", `msg-${i}`),
    );

    const result = getResumeMessages(msgs, 5);
    // Cut should start at index 5 (rough cut) or later at a user boundary.
    // Index 5 is assistant, so it should advance to index 6 which is user.
    expect(result.length).toBeLessThanOrEqual(5);
    expect(result[0].role).toBe("user");
  });

  it("preserves tool-call / tool-result pairs by cutting at user boundary", () => {
    const msgs: ModelMessage[] = [
      makeMsg("user", "start"),
      makeMsg("assistant", [
        { type: "text", text: "I'll scan" },
        {
          type: "tool-call",
          toolCallId: "tc-1",
          toolName: "cmd",
          args: { cmd: "ls" },
        },
      ]),
      makeMsg("tool", [
        {
          type: "tool-result",
          toolCallId: "tc-1",
          toolName: "cmd",
          result: "ok",
        },
      ]),
      makeMsg("assistant", "done with first"),
      makeMsg("user", "next step"),
      makeMsg("assistant", "doing next"),
    ];

    // Limit 3 → rough cut at index 3 ("done with first"), then advance
    // to index 4 ("next step" user msg) for a clean boundary.
    const result = getResumeMessages(msgs, 3);
    expect(result[0].role).toBe("user");
    expect((result[0] as { content: string }).content).toBe("next step");
    expect(result.length).toBe(2);
  });

  it("handles conversations with no user messages after cut point", () => {
    // All assistant messages except the first
    const msgs: ModelMessage[] = [
      makeMsg("user", "go"),
      ...Array.from({ length: 20 }, (_, i) =>
        makeMsg("assistant", `step-${i}`),
      ),
    ];

    // Limit 5 → rough cut at index 16, no user message after that → fallback
    const result = getResumeMessages(msgs, 5);
    expect(result.length).toBe(5);
  });

  it("returns empty array for empty input", () => {
    expect(getResumeMessages([], 10)).toEqual([]);
  });

  it("works with default limit (does not throw)", () => {
    const msgs: ModelMessage[] = [
      makeMsg("user", "hello"),
      makeMsg("assistant", "hi"),
    ];
    expect(() => getResumeMessages(msgs)).not.toThrow();
    expect(getResumeMessages(msgs)).toEqual(msgs);
  });
});

// ---------------------------------------------------------------------------
// normalizeMessages
// ---------------------------------------------------------------------------

describe("normalizeMessages", () => {
  it("returns identical array when messages already alternate", () => {
    const msgs: ModelMessage[] = [
      makeMsg("user", "hello"),
      makeMsg("assistant", "hi"),
      makeMsg("user", "scan"),
      makeMsg("assistant", "scanning..."),
    ];
    expect(normalizeMessages(msgs)).toEqual(msgs);
  });

  it("merges consecutive string user messages", () => {
    const msgs: ModelMessage[] = [
      makeMsg("user", "first"),
      makeMsg("user", "second"),
      makeMsg("user", "third"),
    ];
    const result = normalizeMessages(msgs);
    expect(result).toHaveLength(1);
    expect(result[0].role).toBe("user");
    expect((result[0] as { content: string }).content).toBe(
      "first\n\nsecond\n\nthird",
    );
  });

  it("replaces consecutive structured-content user messages with the latest", () => {
    const msgs: ModelMessage[] = [
      makeMsg("user", [{ type: "text", text: "old" }]),
      makeMsg("user", "new prompt"),
    ];
    const result = normalizeMessages(msgs);
    expect(result).toHaveLength(1);
    expect((result[0] as { content: string }).content).toBe("new prompt");
  });

  it("merges consecutive user messages mid-conversation", () => {
    const msgs: ModelMessage[] = [
      makeMsg("user", "hello"),
      makeMsg("assistant", "hi"),
      makeMsg("user", "retry1"),
      makeMsg("user", "retry2"),
      makeMsg("assistant", "ok"),
    ];
    const result = normalizeMessages(msgs);
    expect(result).toHaveLength(4);
    expect(result[0].role).toBe("user");
    expect(result[1].role).toBe("assistant");
    expect(result[2].role).toBe("user");
    expect((result[2] as { content: string }).content).toBe("retry1\n\nretry2");
    expect(result[3].role).toBe("assistant");
  });

  it("handles empty array", () => {
    expect(normalizeMessages([])).toEqual([]);
  });

  it("handles single message", () => {
    const msgs: ModelMessage[] = [makeMsg("user", "solo")];
    expect(normalizeMessages(msgs)).toEqual(msgs);
  });

  it("preserves tool messages", () => {
    const msgs: ModelMessage[] = [
      makeMsg("user", "go"),
      makeMsg("assistant", [
        { type: "text", text: "scanning" },
        {
          type: "tool-call",
          toolCallId: "tc-1",
          toolName: "cmd",
          args: {},
        },
      ]),
      makeMsg("tool", [
        {
          type: "tool-result",
          toolCallId: "tc-1",
          toolName: "cmd",
          result: "ok",
        },
      ]),
      makeMsg("user", "next"),
    ];
    const result = normalizeMessages(msgs);
    expect(result).toEqual(msgs);
  });

  it("upgrades raw-string tool-result output to structured format", () => {
    const msgs: ModelMessage[] = [
      makeMsg("user", "go"),
      makeMsg("assistant", [
        { type: "text", text: "running" },
        {
          type: "tool-call",
          toolCallId: "tc-1",
          toolName: "cmd",
          input: { cmd: "ls" },
        },
      ]),
      makeMsg("tool", [
        {
          type: "tool-result",
          toolCallId: "tc-1",
          toolName: "cmd",
          output: "Cancelled by user.",
        },
      ]),
    ];
    const result = normalizeMessages(msgs);
    const toolMsg = result.find((m) => m.role === "tool");
    expect(toolMsg).toBeDefined();
    const parts = (toolMsg as { content: Array<Record<string, unknown>> })
      .content;
    expect(parts[0].output).toEqual({
      type: "text",
      value: "Cancelled by user.",
    });
  });

  it("leaves correctly structured tool-result output untouched", () => {
    const msgs: ModelMessage[] = [
      makeMsg("user", "go"),
      makeMsg("tool", [
        {
          type: "tool-result",
          toolCallId: "tc-1",
          toolName: "cmd",
          output: { type: "json", value: { ok: true } },
        },
      ]),
    ];
    const result = normalizeMessages(msgs);
    const parts = (
      result.find((m) => m.role === "tool") as {
        content: Array<Record<string, unknown>>;
      }
    ).content;
    expect(parts[0].output).toEqual({ type: "json", value: { ok: true } });
  });
});
