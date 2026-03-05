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
});
