export type EngagementWorkPriority = "chain" | "retry" | "baseline";

interface QueuedWork<T> {
  run: () => Promise<T>;
  resolve: (value: T) => void;
  reject: (error: unknown) => void;
}

const PRIORITIES: EngagementWorkPriority[] = ["chain", "retry", "baseline"];

/** Shared bounded queue for deterministic coverage and lead-directed workers. */
export class EngagementWorkerPool {
  private active = 0;
  private readonly queues = new Map<
    EngagementWorkPriority,
    Array<QueuedWork<unknown>>
  >(PRIORITIES.map((priority) => [priority, []]));

  constructor(private readonly concurrency: number) {
    if (!Number.isInteger(concurrency) || concurrency < 1) {
      throw new Error(
        "Engagement worker concurrency must be a positive integer",
      );
    }
  }

  run<T>(priority: EngagementWorkPriority, work: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queues.get(priority)?.push({
        run: work,
        resolve: resolve as (value: unknown) => void,
        reject,
      });
      this.drain();
    });
  }

  private drain(): void {
    while (this.active < this.concurrency) {
      const next = PRIORITIES.flatMap(
        (priority) => this.queues.get(priority) ?? [],
      )[0];
      if (!next) return;
      for (const priority of PRIORITIES) {
        const queue = this.queues.get(priority);
        if (queue?.[0] === next) {
          queue.shift();
          break;
        }
      }
      this.active += 1;
      void next
        .run()
        .then(next.resolve, next.reject)
        .finally(() => {
          this.active -= 1;
          this.drain();
        });
    }
  }
}
