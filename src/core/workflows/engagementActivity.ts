import { randomUUID } from "node:crypto";

export const ENGAGEMENT_ACTIVITY_KINDS = [
  "worker-progress",
  "worker-completed",
  "worker-failed",
  "worker-needs-lead",
  "mission-completed",
  "handoff",
] as const;

export type EngagementActivityKind = (typeof ENGAGEMENT_ACTIVITY_KINDS)[number];

export interface EngagementActivity {
  cursor: string;
  sequence: number;
  timestamp: string;
  kind: EngagementActivityKind;
  workerId?: string;
  missionId?: string;
}

export interface EngagementActivityWaitResult {
  cursor: string;
  reason: "activity" | "timeout" | "runtime-restarted" | "history-truncated";
  activity?: EngagementActivity;
}

interface ActivityWaiter {
  workerIds?: Set<string>;
  resolve: (result: EngagementActivityWaitResult) => void;
  reject: (error: unknown) => void;
  timer?: ReturnType<typeof setTimeout>;
  abortSignal?: AbortSignal;
  onAbort?: () => void;
}

const DEFAULT_HISTORY_LIMIT = 256;
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * In-process, replay-safe notification channel for engagement coordination.
 * The opaque cursor detects host restarts and prevents a read-to-wait race.
 */
export class EngagementActivityBroker {
  private readonly runtimeId = randomUUID();
  private readonly historyLimit: number;
  private readonly history: EngagementActivity[] = [];
  private readonly waiters = new Set<ActivityWaiter>();
  private sequence = 0;

  constructor(options: { historyLimit?: number } = {}) {
    const historyLimit = options.historyLimit ?? DEFAULT_HISTORY_LIMIT;
    if (!Number.isInteger(historyLimit) || historyLimit < 1) {
      throw new Error("Engagement activity history limit must be positive");
    }
    this.historyLimit = historyLimit;
  }

  get pendingWaiterCount(): number {
    return this.waiters.size;
  }

  currentCursor(): string {
    return this.cursorFor(this.sequence);
  }

  publish(input: {
    kind: EngagementActivityKind;
    workerId?: string;
    missionId?: string;
  }): EngagementActivity {
    this.sequence += 1;
    const activity: EngagementActivity = {
      ...input,
      cursor: this.currentCursor(),
      sequence: this.sequence,
      timestamp: new Date().toISOString(),
    };
    this.history.push(activity);
    if (this.history.length > this.historyLimit) this.history.shift();

    for (const waiter of [...this.waiters]) {
      if (!this.matches(waiter.workerIds, activity)) continue;
      this.resolveWaiter(waiter, {
        cursor: activity.cursor,
        reason: "activity",
        activity,
      });
    }
    return activity;
  }

  wait(
    input: {
      afterCursor?: string;
      workerIds?: readonly string[];
      timeoutMs?: number;
      abortSignal?: AbortSignal;
    } = {},
  ): Promise<EngagementActivityWaitResult> {
    const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
      throw new Error("Engagement activity timeout must be non-negative");
    }
    if (input.abortSignal?.aborted) {
      return Promise.reject(this.abortReason(input.abortSignal));
    }

    const workerIds = input.workerIds?.length
      ? new Set(input.workerIds)
      : undefined;
    const parsed = input.afterCursor
      ? this.parseCursor(input.afterCursor)
      : { runtimeId: this.runtimeId, sequence: this.sequence };
    if (parsed.runtimeId !== this.runtimeId) {
      return Promise.resolve({
        cursor: this.currentCursor(),
        reason: "runtime-restarted",
      });
    }
    if (parsed.sequence > this.sequence) {
      throw new Error("Engagement activity cursor is ahead of this runtime");
    }

    const replay = this.history.find(
      (activity) =>
        activity.sequence > parsed.sequence &&
        this.matches(workerIds, activity),
    );
    if (replay) {
      return Promise.resolve({
        cursor: replay.cursor,
        reason: "activity",
        activity: replay,
      });
    }

    const oldestSequence = this.history[0]?.sequence;
    if (oldestSequence !== undefined && parsed.sequence < oldestSequence - 1) {
      return Promise.resolve({
        cursor: this.currentCursor(),
        reason: "history-truncated",
      });
    }

    return new Promise<EngagementActivityWaitResult>((resolve, reject) => {
      const waiter: ActivityWaiter = {
        workerIds,
        resolve,
        reject,
        abortSignal: input.abortSignal,
      };
      waiter.onAbort = () => {
        this.rejectWaiter(
          waiter,
          this.abortReason(input.abortSignal as AbortSignal),
        );
      };
      input.abortSignal?.addEventListener("abort", waiter.onAbort, {
        once: true,
      });
      waiter.timer = setTimeout(() => {
        this.resolveWaiter(waiter, {
          cursor: this.currentCursor(),
          reason: "timeout",
        });
      }, timeoutMs);
      this.waiters.add(waiter);
    });
  }

  dispose(reason: unknown = new Error("Engagement activity broker disposed")) {
    for (const waiter of [...this.waiters]) this.rejectWaiter(waiter, reason);
  }

  private cursorFor(sequence: number): string {
    return `${this.runtimeId}:${sequence}`;
  }

  private parseCursor(cursor: string): {
    runtimeId: string;
    sequence: number;
  } {
    const separator = cursor.lastIndexOf(":");
    const runtimeId = cursor.slice(0, separator);
    const sequence = Number(cursor.slice(separator + 1));
    if (
      separator < 1 ||
      !runtimeId ||
      !Number.isSafeInteger(sequence) ||
      sequence < 0
    ) {
      throw new Error("Invalid engagement activity cursor");
    }
    return { runtimeId, sequence };
  }

  private matches(
    workerIds: ReadonlySet<string> | undefined,
    activity: EngagementActivity,
  ): boolean {
    return (
      !workerIds ||
      Boolean(activity.workerId && workerIds.has(activity.workerId))
    );
  }

  private resolveWaiter(
    waiter: ActivityWaiter,
    result: EngagementActivityWaitResult,
  ): void {
    this.releaseWaiter(waiter);
    waiter.resolve(result);
  }

  private rejectWaiter(waiter: ActivityWaiter, error: unknown): void {
    this.releaseWaiter(waiter);
    waiter.reject(error);
  }

  private releaseWaiter(waiter: ActivityWaiter): void {
    if (!this.waiters.delete(waiter)) return;
    if (waiter.timer) clearTimeout(waiter.timer);
    if (waiter.abortSignal && waiter.onAbort) {
      waiter.abortSignal.removeEventListener("abort", waiter.onAbort);
    }
  }

  private abortReason(signal: AbortSignal): unknown {
    return signal.reason ?? new Error("Engagement activity wait aborted");
  }
}
