import {
  AgentEventBus,
  type AgentEvent,
  type NormalizedError,
} from "../agents/offSecAgent/eventBus";

/**
 * Represents a running agent. Async-iterable for streaming events,
 * with a `.result` promise for the final typed output.
 *
 * The internal {@link AgentEventBus} is created and managed automatically —
 * consumers never need to import or configure it.
 *
 * @typeParam TResult - The typed result produced when the agent finishes.
 *
 * @example Streaming events
 * ```ts
 * const run = runPentestAgent({ target, model, session });
 * for await (const event of run) {
 *   if (event.type === "text-delta") process.stdout.write(event.data.text);
 * }
 * const result = await run.result;
 * ```
 *
 * @example Result-only (ignore streaming)
 * ```ts
 * const { findings } = await runPentestAgent({ target, model, session }).result;
 * ```
 */
export class AgentRun<TResult> implements AsyncIterable<AgentEvent> {
  /** Unique identifier for this run, set at construction time. */
  public readonly id: string = crypto.randomUUID();

  /** Resolves to the typed result after the agent finishes. */
  public readonly result: Promise<TResult>;

  private queue: AgentEvent[] = [];
  private waiting: ((value: IteratorResult<AgentEvent>) => void) | null = null;
  private done = false;
  private error: unknown = undefined;

  /** Monotonic sequence counter, incremented for each event. */
  private _nextSeq = 0;

  /** Ordered history of all events emitted during this run. */
  private _history: AgentEvent[] = [];

  constructor(run: (eventBus: AgentEventBus) => Promise<TResult>) {
    const bus = new AgentEventBus();

    bus.on((event) => {
      this.pushEvent(event);
    });

    this.result = run(bus)
      .then((result) => {
        this.pushEvent({ type: "run-complete" });
        return result;
      })
      .catch((err) => {
        if (isAbortError(err)) {
          this.pushEvent({
            type: "run-cancelled",
            error: this.normalizeError(err),
          });
        } else {
          this.pushEvent({
            type: "run-error",
            error: this.normalizeError(err),
          });
        }
        throw err;
      })
      .finally(() => {
        this.done = true;
        if (this.waiting) {
          const resolve = this.waiting;
          this.waiting = null;
          resolve({ value: undefined as never, done: true });
        }
      });
  }

  /**
   * Returns all events with a sequence number strictly greater than `seq`.
   * Useful for replaying missed events (e.g., after a reconnect).
   */
  eventsAfter(seq: number): AgentEvent[] {
    if (seq < 0) return [...this._history];
    if (seq >= this._history.length) return [];
    return this._history.slice(seq);
  }

  /**
   * Returns the current sequence counter (number of events emitted so far).
   * The next event will have sequence number equal to this value.
   */
  get seq(): number {
    return this._nextSeq;
  }

  /**
   * Returns a shallow copy of the full event history.
   */
  get history(): AgentEvent[] {
    return [...this._history];
  }

  /**
   * Converts an unknown thrown value into a plain {@link NormalizedError} object
   * suitable for serialization across API boundaries.
   */
  normalizeError(err: unknown): NormalizedError {
    if (err instanceof Error) {
      const normalized: NormalizedError = {
        message: err.message,
        name: err.name,
      };
      if ("code" in err && typeof (err as Record<string, unknown>).code === "string") {
        normalized.code = (err as Record<string, unknown>).code as string;
      }
      return normalized;
    }
    if (typeof err === "string") {
      return { message: err };
    }
    return { message: String(err) };
  }

  async *[Symbol.asyncIterator](): AsyncIterableIterator<AgentEvent> {
    while (true) {
      while (this.queue.length > 0) {
        yield this.queue.shift()!;
      }

      if (this.done) return;

      const next = await new Promise<IteratorResult<AgentEvent>>((resolve) => {
        if (this.queue.length > 0) {
          resolve({ value: this.queue.shift()!, done: false });
          return;
        }
        if (this.done) {
          resolve({ value: undefined as never, done: true });
          return;
        }
        this.waiting = resolve;
      });

      if (next.done) return;
      yield next.value;
    }
  }

  /** Internal: record event in history and deliver to iterator consumer. */
  private pushEvent(event: AgentEvent): void {
    this._nextSeq++;
    this._history.push(event);

    if (this.waiting) {
      const resolve = this.waiting;
      this.waiting = null;
      resolve({ value: event, done: false });
    } else {
      this.queue.push(event);
    }
  }
}

/** Detect AbortError from AbortController or similar abort signals. */
function isAbortError(err: unknown): boolean {
  if (err instanceof DOMException && err.name === "AbortError") return true;
  if (err instanceof Error && err.name === "AbortError") return true;
  return false;
}
