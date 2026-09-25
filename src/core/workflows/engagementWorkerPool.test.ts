import { describe, expect, it } from "vitest";
import { EngagementWorkerPool } from "./engagementWorkerPool";

describe("EngagementWorkerPool", () => {
  it("runs lead-directed chain work before queued baseline work", async () => {
    const pool = new EngagementWorkerPool(1);
    const order: string[] = [];
    let releaseFirst!: () => void;
    const first = pool.run("baseline", async () => {
      order.push("baseline-1");
      await new Promise<void>((resolve) => {
        releaseFirst = resolve;
      });
    });
    const second = pool.run("baseline", async () => {
      order.push("baseline-2");
    });
    const chain = pool.run("chain", async () => {
      order.push("chain");
    });

    releaseFirst();
    await Promise.all([first, second, chain]);
    expect(order).toEqual(["baseline-1", "chain", "baseline-2"]);
  });

  it("does not starve baseline work behind chain work", async () => {
    const pool = new EngagementWorkerPool(1);
    const order: string[] = [];
    let releaseFirst!: () => void;
    const first = pool.run("chain", async () => {
      order.push("chain-0");
      await new Promise<void>((resolve) => {
        releaseFirst = resolve;
      });
    });
    const chains = [1, 2, 3, 4].map((id) =>
      pool.run("chain", async () => {
        order.push(`chain-${id}`);
      }),
    );
    const baseline = pool.run("baseline", async () => {
      order.push("baseline");
    });

    releaseFirst();
    await Promise.all([first, ...chains, baseline]);
    expect(order).toEqual([
      "chain-0",
      "chain-1",
      "chain-2",
      "baseline",
      "chain-3",
      "chain-4",
    ]);
  });
});
