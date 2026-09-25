import { afterEach, describe, expect, it, vi } from "vitest";
import { EngagementActivityBroker } from "./engagementActivity";

afterEach(() => {
  vi.useRealTimers();
});

describe("EngagementActivityBroker", () => {
  it("replays activity published after the caller's cursor", async () => {
    const broker = new EngagementActivityBroker();
    const cursor = broker.currentCursor();
    const activity = broker.publish({
      kind: "worker-progress",
      workerId: "worker-1",
      missionId: "mission-1",
    });

    await expect(broker.wait({ afterCursor: cursor })).resolves.toEqual({
      cursor: activity.cursor,
      reason: "activity",
      activity,
    });
  });

  it("waits for matching worker activity without polling", async () => {
    const broker = new EngagementActivityBroker();
    const waiting = broker.wait({
      afterCursor: broker.currentCursor(),
      workerIds: ["worker-2"],
      timeoutMs: 1_000,
    });

    broker.publish({ kind: "worker-completed", workerId: "worker-1" });
    expect(broker.pendingWaiterCount).toBe(1);
    const matching = broker.publish({
      kind: "worker-completed",
      workerId: "worker-2",
    });

    await expect(waiting).resolves.toMatchObject({
      cursor: matching.cursor,
      reason: "activity",
      activity: matching,
    });
    expect(broker.pendingWaiterCount).toBe(0);
  });

  it("times out and releases its waiter", async () => {
    vi.useFakeTimers();
    const broker = new EngagementActivityBroker();
    const waiting = broker.wait({ timeoutMs: 500 });

    expect(broker.pendingWaiterCount).toBe(1);
    await vi.advanceTimersByTimeAsync(500);

    await expect(waiting).resolves.toMatchObject({ reason: "timeout" });
    expect(broker.pendingWaiterCount).toBe(0);
  });

  it("rejects an aborted wait and releases its waiter", async () => {
    const broker = new EngagementActivityBroker();
    const controller = new AbortController();
    const reason = new Error("engagement stopped");
    const waiting = broker.wait({
      timeoutMs: 10_000,
      abortSignal: controller.signal,
    });

    controller.abort(reason);

    await expect(waiting).rejects.toBe(reason);
    expect(broker.pendingWaiterCount).toBe(0);
  });

  it("returns immediately when a cursor belongs to an earlier runtime", async () => {
    const first = new EngagementActivityBroker();
    const restarted = new EngagementActivityBroker();

    await expect(
      restarted.wait({ afterCursor: first.currentCursor() }),
    ).resolves.toMatchObject({ reason: "runtime-restarted" });
    expect(restarted.pendingWaiterCount).toBe(0);
  });

  it("reports when the requested replay window was truncated", async () => {
    const broker = new EngagementActivityBroker({ historyLimit: 1 });
    const cursor = broker.currentCursor();
    broker.publish({ kind: "worker-progress", workerId: "worker-1" });
    broker.publish({ kind: "worker-progress", workerId: "worker-2" });

    await expect(
      broker.wait({ afterCursor: cursor, workerIds: ["worker-1"] }),
    ).resolves.toMatchObject({ reason: "history-truncated" });
  });

  it("rejects all pending waits when disposed", async () => {
    const broker = new EngagementActivityBroker();
    const waiting = broker.wait({ timeoutMs: 10_000 });
    const reason = new Error("disposed");

    broker.dispose(reason);

    await expect(waiting).rejects.toBe(reason);
    expect(broker.pendingWaiterCount).toBe(0);
  });
});
