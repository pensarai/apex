import { describe, it, expect } from "vitest";
import { runWithBoundedConcurrency } from "./concurrency";

describe("runWithBoundedConcurrency", () => {
  it("respects concurrency limit", async () => {
    let maxActive = 0;
    let active = 0;

    const items = [1, 2, 3, 4, 5];
    await runWithBoundedConcurrency(items, 2, async (item) => {
      active++;
      if (active > maxActive) maxActive = active;
      await new Promise((r) => setTimeout(r, 10));
      active--;
      return item * 2;
    });

    expect(maxActive).toBe(2);
  });

  it("returns results in input order regardless of completion order", async () => {
    const items = [30, 10, 20]; // delays in ms
    const results = await runWithBoundedConcurrency(items, 3, async (delay) => {
      await new Promise((r) => setTimeout(r, delay));
      return delay;
    });

    expect(results).toEqual([30, 10, 20]);
  });

  it("failed tasks produce null without blocking others", async () => {
    const items = [1, 2, 3, 4];
    const results = await runWithBoundedConcurrency(items, 2, async (item) => {
      if (item === 2 || item === 3) throw new Error("fail");
      return item;
    });

    expect(results).toEqual([1, null, null, 4]);
  });

  it("handles empty input array", async () => {
    const results = await runWithBoundedConcurrency([], 5, async (item) => {
      return item;
    });

    expect(results).toEqual([]);
  });

  it("passes index parameter correctly", async () => {
    const items = ["a", "b", "c"];
    const indices: number[] = [];

    await runWithBoundedConcurrency(items, 2, async (_item, index) => {
      indices.push(index);
      return index;
    });

    expect(indices.sort()).toEqual([0, 1, 2]);
  });

  describe("abort signal", () => {
    it("awaits in-flight tasks after abort and captures their results", async () => {
      const controller = new AbortController();
      const items = [1, 2, 3, 4, 5];
      const executed: number[] = [];

      const results = await runWithBoundedConcurrency(
        items,
        2,
        async (item) => {
          executed.push(item);
          // Abort on the second item — both 1 and 2 are already launched
          // since the while loop starts both before either yields
          if (item === 2) controller.abort();
          await new Promise((r) => setTimeout(r, 10));
          return item * 10;
        },
        controller.signal,
      );

      // Tasks 1 and 2 were launched before abort — both must complete
      expect(executed).toContain(1);
      expect(executed).toContain(2);
      expect(results[0]).toBe(10);
      expect(results[1]).toBe(20);

      // Tasks 3-5 should not have been launched
      expect(executed).not.toContain(3);
      expect(executed).not.toContain(4);
      expect(executed).not.toContain(5);
    });

    it("resolves immediately when aborted before any launch", async () => {
      const controller = new AbortController();
      controller.abort();
      const executed: number[] = [];

      const results = await runWithBoundedConcurrency(
        [1, 2, 3],
        2,
        async (item) => {
          executed.push(item);
          return item;
        },
        controller.signal,
      );

      expect(executed).toEqual([]);
      expect(results).toEqual([null, null, null]);
    });

    it("does not launch new tasks after abort", async () => {
      const controller = new AbortController();
      const items = [10, 20, 30, 40];
      let launchCount = 0;

      await runWithBoundedConcurrency(
        items,
        1, // concurrency=1 so tasks run sequentially
        async (item) => {
          launchCount++;
          if (item === 20) controller.abort();
          await new Promise((r) => setTimeout(r, 5));
          return item;
        },
        controller.signal,
      );

      // Task 1 completes, launches task 2, task 2 aborts — task 3 should never start
      expect(launchCount).toBe(2);
    });
  });
});
