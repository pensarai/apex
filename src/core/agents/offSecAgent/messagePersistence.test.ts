import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentMessageWriter } from "./messagePersistence";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "agent-writer-test-"));
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function path(): string {
  return join(tmpDir, "messages.json");
}

function msgs(...texts: string[]): ModelMessage[] {
  return texts.map((text) => ({
    role: "user" as const,
    content: [{ type: "text" as const, text }],
  }));
}

function read(): ModelMessage[] {
  return JSON.parse(readFileSync(path(), "utf-8"));
}

// ---------------------------------------------------------------------------
// AgentMessageWriter
// ---------------------------------------------------------------------------

describe("AgentMessageWriter", () => {
  it("enqueueWrite writes the exact JSON, file format unchanged", async () => {
    const writer = new AgentMessageWriter({ messagesPath: path() });
    const messages = msgs("hello");
    await writer.enqueueWrite(messages);

    expect(read()).toEqual(messages);
    expect(readFileSync(path(), "utf-8")).toBe(JSON.stringify(messages));
  });

  it("serializes writes: a queued write never starts before the previous settles", async () => {
    const order: string[] = [];
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((r) => (releaseFirst = r));

    const writer = new AgentMessageWriter({
      messagesPath: path(),
      writeImpl: async (_p, contents) => {
        if (contents === JSON.stringify(msgs("first"))) {
          order.push("first:start");
          await firstGate;
          order.push("first:end");
          return;
        }
        order.push(`second:start:${contents.includes("second")}`);
      },
    });

    const first = writer.enqueueWrite(msgs("first"));
    const second = writer.enqueueWrite(msgs("first", "second"));

    // Give the microtask queue a chance — the second write must not start.
    await Promise.resolve();
    await Promise.resolve();
    expect(order).toEqual(["first:start"]);

    releaseFirst();
    await Promise.all([first, second]);
    expect(order).toEqual(["first:start", "first:end", "second:start:true"]);
  });

  it("a failed write rejects its caller but does not poison the queue", async () => {
    let failNext = true;
    const writer = new AgentMessageWriter({
      messagesPath: path(),
      writeImpl: async (_p, _contents) => {
        if (failNext) {
          failNext = false;
          throw new Error("disk full");
        }
        return Promise.resolve();
      },
    });

    await expect(writer.enqueueWrite(msgs("doomed"))).rejects.toThrow(
      "disk full",
    );
    // The queue still works, and the tail was not left rejected.
    await writer.enqueueWrite(msgs("after"));
    expect(writer.waitForPendingWrites()).resolves.toBeUndefined();
  });

  it("schedulePersist debounces; cancelTimer prevents the write and retains latest", () => {
    vi.useFakeTimers();
    try {
      const writer = new AgentMessageWriter({ messagesPath: path() });
      writer.setLatest(msgs("pending"));
      writer.schedulePersist();
      // Re-schedule is a no-op while one timer is pending.
      writer.schedulePersist();

      vi.advanceTimersByTime(14_999);
      expect(() => read()).toThrow(); // nothing written yet

      writer.cancelTimer();
      vi.advanceTimersByTime(60_000);
      expect(() => read()).toThrow(); // cancelled — never written
      expect(writer.latest).toEqual(msgs("pending")); // retained
    } finally {
      vi.useRealTimers();
    }
  });

  it("the debounce flush writes latest and clears it only on success", async () => {
    vi.useFakeTimers();
    try {
      const written: string[] = [];
      const writer = new AgentMessageWriter({
        messagesPath: path(),
        writeImpl: async (_p, contents) => {
          written.push(contents);
        },
      });
      writer.setLatest(msgs("flush-me"));
      writer.schedulePersist();
      await vi.advanceTimersByTimeAsync(15_000);

      expect(written).toEqual([JSON.stringify(msgs("flush-me"))]);
      expect(writer.latest).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it("a guarded clear keeps a newer snapshot recorded during the debounced write", async () => {
    vi.useFakeTimers();
    try {
      let releaseWrite!: () => void;
      const gate = new Promise<void>((r) => (releaseWrite = r));
      const writer = new AgentMessageWriter({
        messagesPath: path(),
        writeImpl: async (_p, contents) => {
          if (contents.includes("old")) {
            await gate;
          }
        },
      });

      writer.setLatest(msgs("old"));
      writer.schedulePersist();
      await vi.advanceTimersByTimeAsync(15_000); // write now gated in flight

      writer.setLatest(msgs("old", "new")); // newer snapshot arrives
      releaseWrite();
      await vi.advanceTimersByTimeAsync(0);

      // The guarded clear must NOT drop the newer snapshot.
      expect(writer.latest).toEqual(msgs("old", "new"));
    } finally {
      vi.useRealTimers();
    }
  });

  it("failed debounced write retains latest for the next flush", async () => {
    vi.useFakeTimers();
    try {
      let failures = 1;
      const writer = new AgentMessageWriter({
        messagesPath: path(),
        writeImpl: async () => {
          if (failures > 0) {
            failures--;
            throw new Error("transient");
          }
        },
      });

      writer.setLatest(msgs("keep-me"));
      writer.schedulePersist();
      await vi.advanceTimersByTimeAsync(15_000);
      expect(writer.latest).toEqual(msgs("keep-me")); // retained on failure

      writer.schedulePersist();
      await vi.advanceTimersByTimeAsync(15_000);
      // Retained snapshot gets retried by the next debounce.
      expect(failures).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("final flush composes cancelTimer + enqueueWrite (the onFinish path)", async () => {
    vi.useFakeTimers();
    try {
      const writer = new AgentMessageWriter({ messagesPath: path() });
      writer.setLatest(msgs("step-1"));
      writer.schedulePersist();
      writer.cancelTimer();

      const final = msgs("step-1", "final");
      writer.setLatest(final);
      await writer.enqueueWrite(final);

      expect(read()).toEqual(final);
      vi.advanceTimersByTime(60_000); // cancelled timer never fires
    } finally {
      vi.useRealTimers();
    }
  });

  it("abort-write ordering: the snapshot queues behind an in-flight write", async () => {
    let releaseFirst!: () => void;
    const gate = new Promise<void>((r) => (releaseFirst = r));
    const writes: string[] = [];
    const writer = new AgentMessageWriter({
      messagesPath: path(),
      writeImpl: async (_p, contents) => {
        writes.push(contents);
        if (writes.length === 1) await gate;
        return;
      },
    });

    const inFlight = writer.enqueueWrite(msgs("base")).catch(() => {});
    const snapshot = writer.enqueueWrite(msgs("base", "abort-snapshot"));

    await Promise.resolve();
    await Promise.resolve();
    expect(writes).toHaveLength(1); // snapshot waits

    releaseFirst();
    await Promise.all([inFlight, snapshot]);
    expect(writes).toHaveLength(2);
    // Ordering preserved: base first, snapshot second.
    expect(JSON.parse(writes[1] ?? "")).toEqual(msgs("base", "abort-snapshot"));
  });

  it("waitForPendingWrites drains the queue completely", async () => {
    const writer = new AgentMessageWriter({
      messagesPath: path(),
      writeImpl: async (_p, _contents) => {
        await new Promise((r) => setTimeout(r, 5));
        return;
      },
    });

    const w1 = writer.enqueueWrite(msgs("a")).catch(() => {});
    const w2 = writer.enqueueWrite(msgs("a", "b")).catch(() => {});
    const w3 = writer.enqueueWrite(msgs("a", "b", "c")).catch(() => {});
    await writer.waitForPendingWrites();
    await Promise.all([w1, w2, w3]);
    // After the drain, the tail is settled and stable.
    const tail = (writer as unknown as { tail: Promise<void> }).tail;
    await expect(tail).resolves.toBeUndefined();
  });

  it("syntheticsPersisted starts false and only marks on demand", () => {
    const writer = new AgentMessageWriter({ messagesPath: path() });
    expect(writer.syntheticsPersisted).toBe(false);
    writer.markSyntheticsPersisted();
    expect(writer.syntheticsPersisted).toBe(true);
  });

  it("no path configured: enqueueWrite and latest are safe no-ops", async () => {
    const writer = new AgentMessageWriter({ messagesPath: null });
    await expect(writer.enqueueWrite(msgs("x"))).resolves.toBeUndefined();
    writer.setLatest(msgs("x"));
    expect(writer.latest).toEqual(msgs("x"));
    expect(writer.messagesPath).toBeNull();
  });
});
