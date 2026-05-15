import type { SessionID } from "./ids.ts";
import type { ApexMessage } from "./messages.ts";

/**
 * A `Run` is the public, async-iterable handle returned by `agent.run(...)`
 * (and `Subagent.spawn(...)`). Consumers iterate `for await (const msg of run) { ... }`
 * to receive the typed `ApexMessage` stream.
 *
 * The Vercel-AI / Claude-SDK shape: messages flow until either `done` is
 * emitted or `abort()` is called.
 */
export interface Run extends AsyncIterable<ApexMessage> {
  readonly sessionId: SessionID;
  /** Resolves with the final result payload from the `done` message. */
  result(): Promise<unknown>;
  /** Aborts the run. Idempotent; subsequent iterators terminate. */
  abort(reason?: unknown): void;
}

/**
 * Adapter — wrap a `(emit) => Promise<unknown>` producer into a `Run`.
 * The producer calls `emit(msg)` for each `ApexMessage`, resolves with the
 * final result, or throws on error.
 */
export function createRun(
  sessionId: SessionID,
  producer: (
    emit: (msg: ApexMessage) => void,
    signal: AbortSignal,
  ) => Promise<unknown>,
): Run {
  const queue: ApexMessage[] = [];
  const waiters: Array<(value: IteratorResult<ApexMessage>) => void> = [];
  let finished = false;
  let abortError: unknown = null;
  let resultValue: unknown;
  let resultResolve!: (v: unknown) => void;
  let resultReject!: (e: unknown) => void;
  const resultPromise = new Promise<unknown>((res, rej) => {
    resultResolve = res;
    resultReject = rej;
  });
  const controller = new AbortController();

  const pushOrResolve = (msg: ApexMessage) => {
    const waiter = waiters.shift();
    if (waiter) waiter({ value: msg, done: false });
    else queue.push(msg);
  };

  const finalize = () => {
    finished = true;
    while (waiters.length > 0) {
      const w = waiters.shift()!;
      w({ value: undefined as unknown as ApexMessage, done: true });
    }
  };

  producer((msg) => pushOrResolve(msg), controller.signal).then(
    (value) => {
      resultValue = value;
      resultResolve(value);
      finalize();
    },
    (err) => {
      abortError = err;
      resultReject(err);
      finalize();
    },
  );

  const iterator: AsyncIterator<ApexMessage> = {
    next(): Promise<IteratorResult<ApexMessage>> {
      if (queue.length > 0) {
        return Promise.resolve({ value: queue.shift()!, done: false });
      }
      if (finished) {
        if (abortError) return Promise.reject(abortError);
        return Promise.resolve({
          value: undefined as unknown as ApexMessage,
          done: true,
        });
      }
      return new Promise((resolve) => waiters.push(resolve));
    },
    return(): Promise<IteratorResult<ApexMessage>> {
      controller.abort();
      finalize();
      return Promise.resolve({
        value: undefined as unknown as ApexMessage,
        done: true,
      });
    },
  };

  // Silence unused — `resultValue` is captured by the promise resolver.
  void resultValue;

  return {
    sessionId,
    [Symbol.asyncIterator]() {
      return iterator;
    },
    result(): Promise<unknown> {
      return resultPromise;
    },
    abort(reason?: unknown): void {
      controller.abort(reason);
      if (!finished) {
        abortError = reason ?? new Error("Run aborted");
        resultReject(abortError);
        finalize();
      }
    },
  };
}
