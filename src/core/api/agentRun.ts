import { AgentEventBus, type AgentEvent } from "../agents/offSecAgent/eventBus";

/**
 * Represents a running agent. Async-iterable for streaming events,
 * with a `.result` promise for the final typed output.
 *
 * The internal {@link AgentEventBus} is created and managed automatically —
 * consumers never need to import or configure it.
 *
 * **Memory note:** Buffered events are kept in memory until consumed via
 * iteration. If you only `await run.result` without iterating, the buffer
 * is freed automatically when the run finishes.
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
  /** Resolves to the typed result after the agent finishes. */
  public readonly result: Promise<TResult>;

  private queue: AgentEvent[] = [];
  private waiting: ((value: IteratorResult<AgentEvent>) => void) | null = null;
  private done = false;
  private iteratorCreated = false;

  constructor(run: (eventBus: AgentEventBus) => Promise<TResult>) {
    const bus = new AgentEventBus();

    bus.on((event) => {
      this.pushEvent(event);
    });

    this.result = run(bus).finally(() => {
      this.done = true;

      // Free buffered events when no iterator was created (result-only consumers).
      // We only clear when !iteratorCreated because .finally() can fire as a
      // microtask between iterator yields, which would drop undelivered events.
      if (!this.iteratorCreated) {
        this.queue.length = 0;
      }

      if (this.waiting) {
        const resolve = this.waiting;
        this.waiting = null;
        resolve({ value: undefined as never, done: true });
      }
    });
  }

  async *[Symbol.asyncIterator](): AsyncIterableIterator<AgentEvent> {
    this.iteratorCreated = true;
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

  /** Internal: deliver event to iterator consumer. */
  private pushEvent(event: AgentEvent): void {
    if (this.waiting) {
      const resolve = this.waiting;
      this.waiting = null;
      resolve({ value: event, done: false });
    } else {
      this.queue.push(event);
    }
  }
}
