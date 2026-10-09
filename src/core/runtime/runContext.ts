import { isDeepStrictEqual } from "node:util";
import type { ModelMessage } from "ai";
import { RunPersistenceError } from "./persistenceError";
import { RunControlInterruption } from "./runControlStore";

/** Epoch counts replacements; revision orders all commits. Both begin at 1. */
export interface ContextReference {
  epoch: number;
  revision: number;
}

/** One committed context change: a new-epoch replacement or an in-epoch extension. */
export type ContextChange =
  | { kind: "replace"; messages: ModelMessage[]; system: string | null }
  | { kind: "append"; messages: ModelMessage[] };

/** Commits compare expectedRevision (0 for fresh runs) before advancing it. */
export interface ContextStore {
  commitContext(
    runId: string,
    attemptId: string,
    expectedRevision: number,
    change: ContextChange,
  ): Promise<ContextReference>;
  getContext(
    runId: string,
  ): Promise<
    | (ContextReference & { messages: ModelMessage[]; system: string | null })
    | undefined
  >;
}

interface RunContextRecorderOptions {
  runId: string;
  attemptId: string;
  store: ContextStore;
}

export interface RunContextRecorder {
  /** Select context after commit; deduplicate repeats and latch write failures. */
  checkpoint(input: {
    messages: ModelMessage[];
    system?: string | null;
  }): Promise<void>;
  /** Await queued commits, then reject with the latched failure if any. */
  flush(): Promise<void>;
  /** Deep-detached copy of the last committed messages. */
  latest(): ModelMessage[] | undefined;
}

export function createRunContextRecorder(
  options: RunContextRecorderOptions,
): RunContextRecorder {
  const { runId, attemptId, store } = options;
  let ref: ContextReference | undefined;
  let committed: ModelMessage[] | undefined;
  let system: string | null = null;
  let latched: Error | undefined;
  let tail: Promise<void> = Promise.resolve();

  const latch = (cause: unknown): Error => {
    latched ??=
      cause instanceof RunControlInterruption
        ? cause
        : new RunPersistenceError(cause);
    return latched;
  };

  const checkpoint = (input: {
    messages: ModelMessage[];
    system?: string | null;
  }): Promise<void> => {
    // Snapshot synchronously so later caller mutation cannot reach a commit.
    let messages: ModelMessage[];
    let nextSystem: string | null | undefined;
    try {
      messages = structuredClone(input.messages);
      // Explicit null clears the system; undefined (omitted) preserves it —
      // ?? would conflate the two.
      nextSystem =
        input.system === undefined ? undefined : structuredClone(input.system);
    } catch (cause) {
      return Promise.reject(latch(cause));
    }

    const work = async (): Promise<void> => {
      if (latched) throw latched;
      const effectiveSystem = nextSystem === undefined ? system : nextSystem;
      let change: ContextChange;
      let expected: ContextReference;
      if (!ref || !committed) {
        change = { kind: "replace", messages, system: effectiveSystem };
        expected = { epoch: 1, revision: 1 };
      } else if (
        isDeepStrictEqual(messages, committed) &&
        effectiveSystem === system
      ) {
        return;
      } else if (effectiveSystem !== system) {
        change = { kind: "replace", messages, system: effectiveSystem };
        expected = { epoch: ref.epoch + 1, revision: ref.revision + 1 };
      } else if (isPrefix(committed, messages)) {
        change = {
          kind: "append",
          messages: messages.slice(committed.length),
        };
        expected = { epoch: ref.epoch, revision: ref.revision + 1 };
      } else {
        change = { kind: "replace", messages, system: effectiveSystem };
        expected = { epoch: ref.epoch + 1, revision: ref.revision + 1 };
      }

      let storeRef: ContextReference;
      try {
        storeRef = await store.commitContext(
          runId,
          attemptId,
          ref?.revision ?? 0,
          change,
        );
      } catch (cause) {
        throw latch(cause);
      }
      if (
        storeRef.epoch !== expected.epoch ||
        storeRef.revision !== expected.revision
      ) {
        throw latch(
          new Error(
            `store returned epoch ${storeRef.epoch} revision ${storeRef.revision}; expected epoch ${expected.epoch} revision ${expected.revision}`,
          ),
        );
      }
      // The selection takes effect only after the commit is durable.
      ref = storeRef;
      committed = messages;
      system = effectiveSystem;
    };

    const run = tail.then(work);
    // The tail observes every settlement even when the caller ignores a
    // rejection (the SDK swallows onStepFinish errors); flush() surfaces it.
    tail = run.then(
      () => {},
      () => {},
    );
    return run;
  };

  const flush = async (): Promise<void> => {
    // Drain to stability while new writes keep arriving.
    let drained: Promise<void>;
    do {
      drained = tail;
      await drained;
    } while (drained !== tail);
    if (latched) throw latched;
  };

  return {
    checkpoint,
    flush,
    latest: () => (committed ? structuredClone(committed) : undefined),
  };
}

function isPrefix(base: ModelMessage[], next: ModelMessage[]): boolean {
  if (next.length < base.length) return false;
  return base.every((m, i) => isDeepStrictEqual(m, next[i]));
}
