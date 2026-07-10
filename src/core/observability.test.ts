import {
  type Context,
  type ContextManager,
  context,
  propagation,
  ROOT_CONTEXT,
} from "@opentelemetry/api";
import { beforeAll, describe, expect, it } from "vitest";
import { newSessionId } from "./id/id";
import {
  SESSION_BAGGAGE_KEY,
  withSubagentSessionBaggage,
} from "./observability";

// Minimal synchronous context manager. Without a registered manager, OTel's
// default no-op manager makes `context.with` a passthrough and drops baggage.
// The helper and these tests are fully synchronous, so a plain stack suffices
// (avoids depending on @opentelemetry/context-async-hooks, which apex does not
// declare directly).
class SyncContextManager implements ContextManager {
  private stack: Context[] = [];
  active(): Context {
    return this.stack[this.stack.length - 1] ?? ROOT_CONTEXT;
  }
  with<A extends unknown[], F extends (...args: A) => ReturnType<F>>(
    ctx: Context,
    fn: F,
    thisArg?: ThisParameterType<F>,
    ...args: A
  ): ReturnType<F> {
    this.stack.push(ctx);
    try {
      return fn.call(thisArg, ...args);
    } finally {
      this.stack.pop();
    }
  }
  bind<T>(_ctx: Context, target: T): T {
    return target;
  }
  enable(): this {
    return this;
  }
  disable(): this {
    return this;
  }
}

beforeAll(() => {
  context.setGlobalContextManager(new SyncContextManager());
});

// ---------------------------------------------------------------------------
// Per-subagent `pensar.session.id` baggage: each subagent's span subtree must
// carry its OWN ses_ execution-session id, while the dispatched root
// (`pensar.root_session.id`) is left untouched.
// ---------------------------------------------------------------------------

const ROOT_BAGGAGE_KEY = "pensar.root_session.id";

function activeSessionId(): string | undefined {
  return propagation.getActiveBaggage()?.getEntry(SESSION_BAGGAGE_KEY)?.value;
}

function activeRootSessionId(): string | undefined {
  return propagation.getActiveBaggage()?.getEntry(ROOT_BAGGAGE_KEY)?.value;
}

/** Seed the "dispatched root" baggage the Console middleware sets, then run fn. */
function withRootBaggage<T>(rootId: string, fn: () => T): T {
  const baggage = propagation
    .createBaggage()
    .setEntry(ROOT_BAGGAGE_KEY, { value: rootId })
    .setEntry(SESSION_BAGGAGE_KEY, { value: rootId });
  return context.with(propagation.setBaggage(context.active(), baggage), fn);
}

describe("withSubagentSessionBaggage", () => {
  it("mints a real ses_ id for a subagent (spawn-site invariant)", () => {
    expect(newSessionId()).toMatch(/^ses_/);
  });

  it("overrides pensar.session.id with the subagent's ses_ id", () => {
    const child = newSessionId();
    withSubagentSessionBaggage(child, () => {
      expect(activeSessionId()).toBe(child);
    });
  });

  it("sets the subagent session but leaves the root session untouched", () => {
    const root = newSessionId();
    const child = newSessionId();
    expect(root).not.toBe(child);

    withRootBaggage(root, () => {
      // Sanity: before the override, session == root (the inherited default).
      expect(activeSessionId()).toBe(root);
      expect(activeRootSessionId()).toBe(root);

      withSubagentSessionBaggage(child, () => {
        // session flips to the child's own ses_ …
        expect(activeSessionId()).toBe(child);
        // … but the dispatched root is preserved for the subtree.
        expect(activeRootSessionId()).toBe(root);
      });

      // Scope restored after the child context closes.
      expect(activeSessionId()).toBe(root);
    });
  });

  it("does NOT override for the top-level agent (undefined session id)", () => {
    const root = newSessionId();
    withRootBaggage(root, () => {
      withSubagentSessionBaggage(undefined, () => {
        expect(activeSessionId()).toBe(root);
        expect(activeRootSessionId()).toBe(root);
      });
    });
  });

  it("does NOT override for a non-ses_ id (e.g. a legacy slug)", () => {
    const root = newSessionId();
    withRootBaggage(root, () => {
      withSubagentSessionBaggage("attack-surface-agent", () => {
        expect(activeSessionId()).toBe(root);
      });
    });
  });

  it("does NOT override for a composite id (e.g. `${ses_}-plan`)", () => {
    const root = newSessionId();
    const worker = newSessionId();
    // The plan agent's routing id is the worker's ses_ + a suffix. It passes
    // isSessionId (startsWith ses_) but is NOT a real agent_sessions id, so it
    // must be rejected and inherit the parent session rather than stamp a bogus
    // composite as pensar.session.id.
    withRootBaggage(root, () => {
      withSubagentSessionBaggage(`${worker}-plan`, () => {
        expect(activeSessionId()).toBe(root);
      });
    });
  });

  it("still sets the baggage when there is no active baggage to inherit", () => {
    const child = newSessionId();
    withSubagentSessionBaggage(child, () => {
      expect(activeSessionId()).toBe(child);
    });
  });
});
