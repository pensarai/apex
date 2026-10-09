import type { ModelMessage } from "ai";
import { describe, expect, it, vi } from "vitest";
import { RunPersistenceError } from "./persistenceError";
import {
  type ContextChange,
  type ContextStore,
  createRunContextRecorder,
} from "./runContext";

type CommitCall = {
  expectedRevision: number;
  change: ContextChange;
};

/**
 * In-memory store with the documented reference arithmetic: revision is
 * always expectedRevision + 1; a replace opens epoch (prior + 1), the very
 * first commit opens epoch 1, an append carries the prior epoch.
 * startEpoch lets seeded recorders carry a pre-existing epoch.
 */
function makeStore(
  script?: { failOn?: number },
  options?: { startEpoch?: number },
) {
  const calls: CommitCall[] = [];
  const baseEpoch = options?.startEpoch ?? 0;
  const epochAfter = (upTo: number): number => {
    let epoch = baseEpoch;
    for (let i = 0; i < upTo; i++) {
      if (calls[i].change.kind === "replace") epoch += 1;
    }
    return epoch;
  };
  const store: ContextStore = {
    async commitContext(runId, attemptId, expectedRevision, change) {
      expect(runId).toBe("run_1");
      expect(attemptId).toBe("attempt_1");
      if (script?.failOn === calls.length + 1) {
        calls.push({ expectedRevision, change });
        throw new Error("disk on fire");
      }
      const epoch = epochAfter(calls.length);
      calls.push({ expectedRevision, change });
      return {
        epoch: change.kind === "replace" ? epoch + 1 : epoch,
        revision: expectedRevision + 1,
      };
    },
    async getContext() {
      return undefined;
    },
  };
  return { store, calls };
}

const user = (text: string): ModelMessage => ({
  role: "user",
  content: [{ type: "text", text }],
});
const assistant = (text: string): ModelMessage => ({
  role: "assistant",
  content: [{ type: "text", text }],
});

function recorder(store: ContextStore) {
  return createRunContextRecorder({
    runId: "run_1",
    attemptId: "attempt_1",
    store,
  });
}

describe("createRunContextRecorder", () => {
  it("first checkpoint is a replace opening epoch 1 revision 1", async () => {
    const { store, calls } = makeStore();
    const r = recorder(store);
    await r.checkpoint({ messages: [user("a")], system: "sys" });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({
      expectedRevision: 0,
      change: {
        kind: "replace",
        messages: [user("a")],
        system: "sys",
      },
    });
    expect(r.latest()).toEqual([user("a")]);
  });

  it("exact prior-prefix extension appends only the delta", async () => {
    const { store, calls } = makeStore();
    const r = recorder(store);
    await r.checkpoint({ messages: [user("a")], system: "sys" });
    await r.checkpoint({
      messages: [user("a"), assistant("b"), user("c")],
      system: "sys",
    });
    expect(calls[1]?.change).toEqual({
      kind: "append",
      messages: [assistant("b"), user("c")],
    });
    expect(calls[1]?.expectedRevision).toBe(1);
    expect(r.latest()).toEqual([user("a"), assistant("b"), user("c")]);
  });

  it("identical content and system is skipped (dedup)", async () => {
    const { store, calls } = makeStore();
    const r = recorder(store);
    await r.checkpoint({ messages: [user("a")], system: "sys" });
    await r.checkpoint({ messages: [user("a")], system: "sys" });
    // Omitted system preserves; still a duplicate.
    await r.checkpoint({ messages: [user("a")] });
    expect(calls).toHaveLength(1);
  });

  it("rewrite that is not a prefix replaces and opens a new epoch", async () => {
    const { store, calls } = makeStore();
    const r = recorder(store);
    await r.checkpoint({ messages: [user("a"), user("b")], system: "sys" });
    await r.checkpoint({ messages: [user("a")], system: "sys" });
    expect(calls[1]?.change.kind).toBe("replace");
    expect(calls[1]?.change.kind === "replace" && calls[1].change.system).toBe(
      "sys",
    );
    expect(
      calls[1]?.change.kind === "replace" && calls[1].change.messages,
    ).toEqual([user("a")]);
  });

  it("changed system replaces and opens a new epoch even for equal messages", async () => {
    const { store, calls } = makeStore();
    const r = recorder(store);
    await r.checkpoint({ messages: [user("a")], system: "old" });
    await r.checkpoint({ messages: [user("a")], system: "new" });
    expect(calls).toHaveLength(2);
    expect(calls[1]?.change).toEqual({
      kind: "replace",
      messages: [user("a")],
      system: "new",
    });
  });

  it("explicit null clears the system; omitted preserves it", async () => {
    const { store, calls } = makeStore();
    const r = recorder(store);
    await r.checkpoint({ messages: [user("a")], system: "sys" });
    await r.checkpoint({ messages: [user("a"), assistant("b")] });
    expect(calls).toHaveLength(2); // preserved system → pure append
    await r.checkpoint({ messages: [user("a"), assistant("b")], system: null });
    expect(calls[2]?.change).toEqual({
      kind: "replace",
      messages: [user("a"), assistant("b")],
      system: null,
    });
  });

  it("commits are serialized in call order", async () => {
    const { store, calls } = makeStore();
    const r = recorder(store);
    const first = r.checkpoint({ messages: [user("a")], system: "s" });
    const second = r.checkpoint({
      messages: [user("a"), assistant("b")],
      system: "s",
    });
    await Promise.all([first, second]);
    expect(calls.map((c) => c.expectedRevision)).toEqual([0, 1]);
  });

  it("caller mutation after checkpoint does not affect the commit", async () => {
    const { store, calls } = makeStore();
    const r = recorder(store);
    const messages = [user("a")];
    const pending = r.checkpoint({ messages, system: "s" });
    messages[0] = user("mutated");
    messages.push(assistant("injected"));
    await pending;
    expect(
      calls[0]?.change.kind === "replace" && calls[0].change.messages,
    ).toEqual([user("a")]);
  });

  it("input.system is snapshotted synchronously at call time", async () => {
    const { store, calls } = makeStore();
    const r = recorder(store);
    // The AI prepareStep integration reads effectiveSystem ?? null and may
    // mutate the same variable after the call; the recorder must have
    // captured the value before the first await.
    let sys: string | null = "first";
    const pending = r.checkpoint({
      messages: [user("a")],
      get system() {
        return sys;
      },
    });
    sys = "mutated";
    await pending;
    expect(calls[0]?.change.kind === "replace" && calls[0].change.system).toBe(
      "first",
    );
  });

  it("mutation of nested latest() content does not leak into recorder state", async () => {
    const { store } = makeStore();
    const r = recorder(store);
    await r.checkpoint({ messages: [user("a")], system: "s" });
    const snap1 = r.latest();
    if (!snap1) throw new Error("expected a committed snapshot");
    snap1[0].content = [{ type: "text", text: "tampered" }];
    expect(r.latest()).toEqual([user("a")]);
    // And the tampered snapshot does not affect a subsequent dedup check.
    await r.checkpoint({ messages: [user("a")], system: "s" });
    expect(r.latest()).toEqual([user("a")]);
  });

  it("a failed commit latches: later checkpoints and flush fail closed, no store call", async () => {
    const { store, calls } = makeStore({ failOn: 1 });
    const r = recorder(store);
    await expect(
      r.checkpoint({ messages: [user("a")], system: "s" }),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    expect(calls).toHaveLength(1);
    await expect(
      r.checkpoint({ messages: [user("b")], system: "s" }),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    expect(calls).toHaveLength(1); // no second store call
    await expect(r.flush()).rejects.toBeInstanceOf(RunPersistenceError);
    expect(r.latest()).toBeUndefined(); // failed commit never advanced selection
  });

  it("store reference disagreement latches with the mismatch as cause", async () => {
    const calls: CommitCall[] = [];
    const store: ContextStore = {
      async commitContext(_runId, _attemptId, expectedRevision, change) {
        calls.push({ expectedRevision, change });
        return { epoch: 3, revision: 7 };
      },
      async getContext() {
        return undefined;
      },
    };
    const r = recorder(store);
    const failure = r.checkpoint({ messages: [user("a")], system: "s" });
    await expect(failure).rejects.toBeInstanceOf(RunPersistenceError);
    await expect(failure).rejects.toMatchObject({
      cause: expect.objectContaining({
        message: expect.stringContaining("epoch 3"),
      }),
    });
    expect(r.latest()).toBeUndefined();
    expect(calls).toHaveLength(1);
  });

  it("flush drains to stability while new writes arrive during the drain", async () => {
    const { store, calls } = makeStore();
    const r = recorder(store);
    await r.checkpoint({ messages: [user("a")], system: "s" });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let releaseThird!: () => void;
    const thirdGate = new Promise<void>((resolve) => {
      releaseThird = resolve;
    });
    let enteredThird!: () => void;
    const thirdStarted = new Promise<void>((resolve) => {
      enteredThird = resolve;
    });
    const original = store.commitContext.bind(store);
    vi.spyOn(store, "commitContext")
      .mockImplementationOnce(
        async (...args: Parameters<ContextStore["commitContext"]>) => {
          await gate;
          return original(...args);
        },
      )
      .mockImplementationOnce(async (...args) => {
        enteredThird();
        await thirdGate;
        return original(...args);
      });
    const second = r.checkpoint({
      messages: [user("a"), assistant("b")],
      system: "s",
    });
    let flushed = false;
    const flushing = r.flush().then(() => {
      flushed = true;
    });
    // A write enqueued while flush is draining must be awaited too.
    const third = r.checkpoint({
      messages: [user("a"), assistant("b"), user("c")],
      system: "s",
    });
    release();
    await thirdStarted;
    await new Promise<void>((resolve) => setImmediate(resolve));
    try {
      expect(flushed).toBe(false);
    } finally {
      releaseThird();
      await Promise.all([second, third, flushing]);
    }
    expect(calls.map((c) => c.expectedRevision)).toEqual([0, 1, 2]);
  });

  it("flush rejects with the latched failure even when the caller ignored the rejection", async () => {
    const { store } = makeStore({ failOn: 1 });
    const r = recorder(store);
    // The SDK swallows onStepFinish callback errors — no await, no catch.
    void r.checkpoint({ messages: [user("a")], system: "s" }).catch(() => {});
    // Let the rejected microtask settle.
    await new Promise((resolve) => setTimeout(resolve, 0));
    await expect(r.flush()).rejects.toBeInstanceOf(RunPersistenceError);
  });

  it("structuredClone failure latches and fails closed without touching the store", async () => {
    const { store, calls } = makeStore();
    const r = recorder(store);
    const poisonous = {
      role: "user",
      content: [
        {
          type: "text",
          text: "x",
          get node() {
            throw new Error("uncloneable");
          },
        },
      ],
    } as unknown as ModelMessage;
    await expect(
      r.checkpoint({ messages: [poisonous], system: "s" }),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    expect(calls).toHaveLength(0);
    await expect(
      r.checkpoint({ messages: [user("ok")], system: "s" }),
    ).rejects.toBeInstanceOf(RunPersistenceError);
    expect(calls).toHaveLength(0);
    await expect(r.flush()).rejects.toBeInstanceOf(RunPersistenceError);
  });
});

describe("createRunContextRecorder seeded from a committed head", () => {
  const seed = {
    epoch: 2,
    revision: 5,
    messages: [user("a")],
    system: "sys",
  };

  it("an extending checkpoint appends only the delta at the preserved revision", async () => {
    const { store, calls } = makeStore(undefined, { startEpoch: 2 });
    const r = createRunContextRecorder({
      runId: "run_1",
      attemptId: "attempt_1",
      store,
      initial: seed,
    });

    await r.checkpoint({ messages: [user("a"), assistant("b")] });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({
      expectedRevision: 5,
      change: { kind: "append", messages: [assistant("b")] },
    });
  });

  it("a rewritten head replaces and opens the next epoch", async () => {
    const { store, calls } = makeStore(undefined, { startEpoch: 2 });
    const r = createRunContextRecorder({
      runId: "run_1",
      attemptId: "attempt_1",
      store,
      initial: seed,
    });

    await r.checkpoint({ messages: [assistant("rewritten")] });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({
      expectedRevision: 5,
      change: {
        kind: "replace",
        messages: [assistant("rewritten")],
        system: "sys",
      },
    });
  });

  it("an identical seeded head is deduplicated without a store call", async () => {
    const { store, calls } = makeStore(undefined, { startEpoch: 2 });
    const r = createRunContextRecorder({
      runId: "run_1",
      attemptId: "attempt_1",
      store,
      initial: seed,
    });

    await r.checkpoint({ messages: [user("a")], system: "sys" });

    expect(calls).toHaveLength(0);
  });

  it("latest() serves the seeded head before any checkpoint", () => {
    const { store } = makeStore();
    const r = createRunContextRecorder({
      runId: "run_1",
      attemptId: "attempt_1",
      store,
      initial: seed,
    });

    expect(r.latest()).toEqual([user("a")]);
  });

  it("the seed is deep-cloned synchronously: later mutation cannot reach a commit", async () => {
    const { store, calls } = makeStore(undefined, { startEpoch: 2 });
    const mutable = {
      epoch: 2,
      revision: 5,
      messages: [user("a")],
      system: "sys",
    };
    const r = createRunContextRecorder({
      runId: "run_1",
      attemptId: "attempt_1",
      store,
      initial: mutable,
    });

    mutable.messages.push(user("mutated"));
    mutable.system = "tampered";

    await r.checkpoint({ messages: [user("a"), user("mutated")] });

    expect(calls[0]?.change).toEqual({
      kind: "append",
      messages: [user("mutated")],
    });
    const latest = r.latest();
    expect(latest).toEqual([user("a"), user("mutated")]);
  });
});
