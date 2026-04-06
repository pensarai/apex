import {
  AgentEventBus,
  AGENT_EVENT_NAMES,
  type AgentEvent,
  type AgentEventMap,
} from "../eventBus";

/**
 * A handle to a running agent. Implements `AsyncIterable<AgentEvent>` for
 * pull-based streaming and exposes `.result` for the final typed result.
 *
 * Three consumption patterns:
 *
 * 1. Stream events + get result:
 *    ```ts
 *    const run = runPentestAgent({ ... });
 *    for await (const event of run) { switch (event.type) { ... } }
 *    const { findings } = await run.result;
 *    ```
 *
 * 2. Just get the result (events are buffered and discarded):
 *    ```ts
 *    const { findings } = await runPentestAgent({ ... }).result;
 *    ```
 *
 * 3. Ignore the result, just stream:
 *    ```ts
 *    for await (const event of runPentestAgent({ ... })) { ... }
 *    ```
 */
export class AgentRun<TResult> implements AsyncIterable<AgentEvent> {
  readonly result: Promise<TResult>;

  private readonly eventBus: AgentEventBus;
  private buffer: AgentEvent[] = [];
  private waiting: ((value: IteratorResult<AgentEvent>) => void) | null = null;
  private done = false;
  private error: unknown = undefined;

  constructor(executor: (eventBus: AgentEventBus) => Promise<TResult>) {
    this.eventBus = new AgentEventBus();
    this.subscribeAll();

    this.result = executor(this.eventBus).then(
      (result) => {
        this.done = true;
        this.flush();
        return result;
      },
      (err) => {
        this.done = true;
        this.error = err;
        this.flush();
        throw err;
      },
    );
  }

  private subscribeAll(): void {
    for (const key of AGENT_EVENT_NAMES) {
      this.eventBus.on(key, (payload: AgentEventMap[typeof key]) => {
        const event: AgentEvent = { type: key, data: payload } as AgentEvent;
        if (this.waiting) {
          const resolve = this.waiting;
          this.waiting = null;
          resolve({ value: event, done: false });
        } else {
          this.buffer.push(event);
        }
      });
    }
  }

  private flush(): void {
    if (this.waiting) {
      const resolve = this.waiting;
      this.waiting = null;
      resolve({ value: undefined as unknown as AgentEvent, done: true });
    }
  }

  async *[Symbol.asyncIterator](): AsyncIterableIterator<AgentEvent> {
    while (true) {
      if (this.buffer.length > 0) {
        yield this.buffer.shift()!;
        continue;
      }
      if (this.done) return;
      const result = await new Promise<IteratorResult<AgentEvent>>(
        (resolve) => {
          // Check again after microtask — events may have arrived
          if (this.buffer.length > 0) {
            resolve({ value: this.buffer.shift()!, done: false });
            return;
          }
          if (this.done) {
            resolve({ value: undefined as unknown as AgentEvent, done: true });
            return;
          }
          this.waiting = resolve;
        },
      );
      if (result.done) return;
      yield result.value;
    }
  }
}
