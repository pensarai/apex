import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mintMessageID, mintNodeID, mintPartID, mintSessionID } from "./ids.ts";
import type { ApexMessage } from "./messages.ts";
import { SessionStorage } from "./storage.ts";

describe("sdk/storage — JSONL roundtrip", () => {
  let dataDir: string;

  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), "apex-sdk-storage-"));
    process.env.PENSAR_DATA_DIR = dataDir;
  });

  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
    delete process.env.PENSAR_DATA_DIR;
  });

  it("writes and reads back the same messages in order", async () => {
    const sid = mintSessionID();
    const nid = mintNodeID();
    const mid = mintMessageID();
    const pid = mintPartID();
    const now = new Date().toISOString();

    const messages: ApexMessage[] = [
      {
        type: "node.created",
        node: {
          id: nid,
          sessionId: sid,
          parentId: null,
          parentToolCallId: null,
          sequence: 1,
          kind: "agent",
          state: "running",
          name: "root",
          payload: {},
          createdAt: now,
        },
        sequence: 1,
        timestamp: now,
      },
      {
        type: "message.created",
        message: {
          id: mid,
          nodeId: nid,
          sessionId: sid,
          role: "assistant",
          sequence: 1,
          createdAt: now,
        },
        parts: [
          {
            id: pid,
            type: "text",
            messageId: mid,
            sequence: 0,
            content: { text: "hello" },
          },
        ],
        sequence: 2,
        timestamp: now,
      },
      {
        type: "usage.recorded",
        nodeId: nid,
        model: "claude-opus-4-7",
        tokens: { inputTokens: 100, outputTokens: 50 },
        cost: 0.0042,
        sequence: 3,
        timestamp: now,
      },
      {
        type: "done",
        sessionId: sid,
        result: "ok",
      },
    ];

    const storage = new SessionStorage(sid);
    for (const m of messages) await storage.append(m);

    const readBack = await storage.readAll();
    expect(readBack).toEqual(messages);
  });

  it("file path lives under PENSAR_DATA_DIR/sessions/{id}/events.jsonl", () => {
    const sid = mintSessionID();
    const storage = new SessionStorage(sid);
    expect(storage.filePath).toBe(
      join(dataDir, "sessions", sid, "events.jsonl"),
    );
  });

  it("readAll on missing file returns empty array (not error)", async () => {
    const sid = mintSessionID();
    const storage = new SessionStorage(sid);
    await expect(storage.readAll()).resolves.toEqual([]);
  });

  it("survives ordered concurrent appends", async () => {
    const sid = mintSessionID();
    const storage = new SessionStorage(sid);
    const nid = mintNodeID();
    const now = new Date().toISOString();

    const ops = Array.from({ length: 10 }, (_, i) =>
      storage.append({
        type: "node.state",
        nodeId: nid,
        state: "running",
        reason: `step ${i}`,
        sequence: i + 1,
        timestamp: now,
      }),
    );
    await Promise.all(ops);

    const read = await storage.readAll();
    expect(read).toHaveLength(10);
    // Order may be insertion order (chain serializes)
    expect(
      read.map((m) => (m.type === "node.state" ? m.sequence : -1)),
    ).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });

  it("rejects malformed lines via Zod schema during read", async () => {
    const sid = mintSessionID();
    const storage = new SessionStorage(sid);

    // Inject a malformed line directly.
    await storage.append({
      type: "done",
      sessionId: sid,
      result: null,
    });
    const fs = await import("node:fs/promises");
    await fs.appendFile(
      storage.filePath,
      `${JSON.stringify({ type: "not-a-real-variant" })}\n`,
      "utf-8",
    );

    await expect(storage.readAll()).rejects.toBeDefined();
  });
});
