import {
  type Context,
  type ContextManager,
  context,
  createContextKey,
  ROOT_CONTEXT,
  trace,
} from "@opentelemetry/api";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { startOtelTestHarness } from "./testkit";

class StaleContextManager implements ContextManager {
  active(): Context {
    return ROOT_CONTEXT;
  }

  with<A extends unknown[], F extends (...args: A) => ReturnType<F>>(
    _context: Context,
    fn: F,
    thisArg?: ThisParameterType<F>,
    ...args: A
  ): ReturnType<F> {
    return fn.call(thisArg, ...args);
  }

  bind<T>(_context: Context, target: T): T {
    return target;
  }

  enable(): this {
    return this;
  }

  disable(): this {
    return this;
  }
}

beforeEach(() => {
  trace.disable();
  context.disable();
});

afterEach(() => {
  trace.disable();
  context.disable();
});

describe("startOtelTestHarness", () => {
  it("replaces a previously registered context manager", async () => {
    context.setGlobalContextManager(new StaleContextManager());

    const harness = startOtelTestHarness();
    try {
      const key = createContextKey("testkit-context");
      const expected = ROOT_CONTEXT.setValue(key, "active");

      await context.with(expected, async () => {
        await Promise.resolve();
        expect(context.active().getValue(key)).toBe("active");
      });
    } finally {
      await harness.shutdown();
    }
  });
});
