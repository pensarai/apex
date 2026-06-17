import { AsyncLocalStorage } from "node:async_hooks";
import {
  type Context,
  type ContextManager,
  context,
  createContextKey,
  ROOT_CONTEXT,
} from "@opentelemetry/api";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runWithBoundedConcurrency } from "./concurrency";

// Minimal AsyncLocalStorage context manager — apex ships only @opentelemetry/api,
// so a manager must be registered for context propagation to be observable here.
class TestContextManager implements ContextManager {
  private readonly als = new AsyncLocalStorage<Context>();
  active(): Context {
    return this.als.getStore() ?? ROOT_CONTEXT;
  }
  with<A extends unknown[], F extends (...args: A) => ReturnType<F>>(
    ctx: Context,
    fn: F,
    thisArg?: ThisParameterType<F>,
    ...args: A
  ): ReturnType<F> {
    return this.als.run(ctx, () =>
      fn.apply(thisArg as ThisParameterType<F>, args),
    );
  }
  bind<T>(ctx: Context, target: T): T {
    if (typeof target === "function") {
      const self = this;
      return function (this: unknown, ...args: unknown[]) {
        return self.with(ctx, () =>
          (target as (...a: unknown[]) => unknown).apply(this, args),
        );
      } as T;
    }
    return target;
  }
  enable(): this {
    return this;
  }
  disable(): this {
    this.als.disable();
    return this;
  }
}

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

  describe("trace context propagation", () => {
    beforeAll(() => {
      context.setGlobalContextManager(new TestContextManager());
    });
    afterAll(() => {
      context.disable();
    });

    it("runs every task under the context active at call time, including continuation-launched tasks", async () => {
      const KEY = createContextKey("test-trace-id");
      const seen: (unknown | undefined)[] = [];

      // concurrency=1 makes tasks 1..3 launch from the `.finally()` continuation,
      // the boundary that drops context without the explicit binding.
      await context.with(ROOT_CONTEXT.setValue(KEY, "parent"), async () => {
        await runWithBoundedConcurrency([0, 1, 2, 3], 1, async (i) => {
          await new Promise((r) => setTimeout(r, 1));
          seen[i] = context.active().getValue(KEY);
          return i;
        });
      });

      expect(seen).toEqual(["parent", "parent", "parent", "parent"]);
    });
  });
});
