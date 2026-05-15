import { mkdtempSync, rmSync, readFileSync, existsSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AgentEventBus } from "../eventBus";
import { ExecutionContext } from "./context";
import {
  attachExecutionFileStorage,
  loadSessionFromDisk,
} from "./fileStorage";
import { newSessionId } from "./ids";
import type { ExecutionSession } from "./sessions";

describe("ExecutionFileStorage — write + read parity", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "execfs-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const sampleSession = (id: string): ExecutionSession => ({
    id: id as ExecutionSession["id"],
    workspaceId: "ws_x",
    projectId: null,
    scope: "apex_session",
    title: "test session",
    agent: "offsec",
    model: "claude",
    status: "running",
    timeCreated: new Date().toISOString(),
    timeUpdated: new Date().toISOString(),
    timeCompleted: null,
    cost: null,
    tokensInput: null,
    tokensOutput: null,
    tokensReasoning: null,
    tokensCacheRead: null,
    tokensCacheWrite: null,
    revert: null,
  });

  it("writes session.json on attach", () => {
    const bus = new AgentEventBus();
    const sessionId = newSessionId();
    const session = sampleSession(sessionId);
    const storage = attachExecutionFileStorage({
      bus,
      rootDir: dir,
      session,
    });
    expect(existsSync(join(storage.path, "session.json"))).toBe(true);
    const parsed = JSON.parse(
      readFileSync(join(storage.path, "session.json"), "utf8"),
    );
    expect(parsed.id).toBe(sessionId);
    storage.detach();
  });

  it("appends durable events to events.jsonl + projects to nodes/messages/parts", () => {
    const bus = new AgentEventBus();
    const sessionId = newSessionId();
    const storage = attachExecutionFileStorage({
      bus,
      rootDir: dir,
      session: sampleSession(sessionId),
    });

    const ctx = new ExecutionContext({ sessionId, bus });
    const rootId = ctx.registerNode({
      kind: "agent",
      name: "root",
      initialState: "running",
    });
    ctx.recordMessage({
      nodeId: rootId,
      role: "assistant",
      parts: [{ type: "text", text: "hello" }],
    });
    ctx.completeNode({ nodeId: rootId, result: "done" });
    ctx.emitCommandOutput(rootId, "transient\n");

    const eventsPath = join(storage.path, "events.jsonl");
    const eventsText = readFileSync(eventsPath, "utf8");
    const lines = eventsText.trim().split("\n");
    expect(lines.length).toBe(3);
    const types = lines.map((l) => JSON.parse(l).type as string);
    expect(types).toEqual(["node.created", "message.created", "node.completed"]);

    const nodes = readFileSync(join(storage.path, "nodes.jsonl"), "utf8")
      .trim()
      .split("\n");
    expect(nodes.length).toBe(2);

    storage.detach();
  });

  it("ignores transient events", () => {
    const bus = new AgentEventBus();
    const sessionId = newSessionId();
    const storage = attachExecutionFileStorage({
      bus,
      rootDir: dir,
      session: sampleSession(sessionId),
    });

    const ctx = new ExecutionContext({ sessionId, bus });
    const rootId = ctx.registerNode({
      kind: "agent",
      name: "root",
      initialState: "running",
    });
    ctx.emitCommandOutput(rootId, "transient text\n");

    const events = readFileSync(join(storage.path, "events.jsonl"), "utf8")
      .trim()
      .split("\n");
    expect(events.length).toBe(1);
    expect(JSON.parse(events[0]!).type).toBe("node.created");
    storage.detach();
  });

  it("roundtrips via loadSessionFromDisk", () => {
    const bus = new AgentEventBus();
    const sessionId = newSessionId();
    attachExecutionFileStorage({
      bus,
      rootDir: dir,
      session: sampleSession(sessionId),
    });

    const ctx = new ExecutionContext({ sessionId, bus });
    const rootId = ctx.registerNode({
      kind: "agent",
      name: "root",
      initialState: "running",
    });
    ctx.recordMessage({
      nodeId: rootId,
      role: "assistant",
      parts: [{ type: "text", text: "hi" }],
    });

    const loaded = loadSessionFromDisk(dir, sessionId);
    expect(loaded).toBeTruthy();
    if (loaded) {
      expect(loaded.session.id).toBe(sessionId);
      expect(loaded.events.length).toBe(2);
      expect(loaded.nodes.length).toBe(1);
      expect(loaded.messages.length).toBe(1);
      expect(loaded.parts.length).toBe(1);
    }
  });

  it("loadSessionFromDisk returns null for unknown session", () => {
    const result = loadSessionFromDisk(dir, "ses_does_not_exist");
    expect(result).toBeNull();
  });
});
