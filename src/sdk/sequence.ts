import type { SessionID } from "./ids.ts";

/**
 * Per-session monotonic sequence counter. Each call to `next(sessionId)`
 * returns the next integer for that session. Counters are kept in-memory
 * for the lifetime of the process; durable sequence state is reconstructed
 * from `agent_events.sequence` on resume.
 */
export class SequenceCounter {
  private readonly counters = new Map<SessionID, number>();

  next(sessionId: SessionID): number {
    const current = this.counters.get(sessionId) ?? 0;
    const nextValue = current + 1;
    this.counters.set(sessionId, nextValue);
    return nextValue;
  }

  peek(sessionId: SessionID): number {
    return this.counters.get(sessionId) ?? 0;
  }

  /** Restore counter to a known value (e.g. after replaying events from DB). */
  restore(sessionId: SessionID, value: number): void {
    this.counters.set(sessionId, value);
  }

  reset(sessionId: SessionID): void {
    this.counters.delete(sessionId);
  }
}
