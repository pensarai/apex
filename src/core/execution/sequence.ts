import type { SessionID } from "./ids";

export class SequenceCounter {
  private readonly counters = new Map<SessionID, number>();

  next(sessionId: SessionID): number {
    const current = this.counters.get(sessionId);
    const value = current === undefined ? 0 : current + 1;
    this.counters.set(sessionId, value);
    return value;
  }

  seed(sessionId: SessionID, lastSequence: number): void {
    this.counters.set(sessionId, lastSequence);
  }

  peek(sessionId: SessionID): number | null {
    const value = this.counters.get(sessionId);
    return value === undefined ? null : value;
  }

  forget(sessionId: SessionID): void {
    this.counters.delete(sessionId);
  }
}
