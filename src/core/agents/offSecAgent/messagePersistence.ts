import { writeFile } from "node:fs/promises";
import type { ModelMessage } from "ai";

// ---------------------------------------------------------------------------
// Agent message persistence — the agent-local writer for messages.json.
// Owns the debounce timer, the latest pending snapshot, the serialized write
// queue, and the synthetics-persisted flag. File format and path are
// unchanged; there is no shared session store here.
// ---------------------------------------------------------------------------

const PERSIST_INTERVAL_MS = 15_000;

export interface AgentMessageWriterOptions {
  messagesPath: string | null;
  /** Debounce window for scheduled persists (tests shrink this). */
  intervalMs?: number;
  /** Write sink; defaults to fs/promises writeFile. */
  writeImpl?: (messagesPath: string, contents: string) => Promise<void>;
}

export class AgentMessageWriter {
  private readonly intervalMs: number;
  private readonly writeImpl: (
    messagesPath: string,
    contents: string,
  ) => Promise<void>;
  private readonly path: string | null;

  private pending: ModelMessage[] | null = null;
  private tail: Promise<void> = Promise.resolve();
  private persistTimer: ReturnType<typeof setTimeout> | null = null;
  private syntheticsWritten = false;

  constructor(options: AgentMessageWriterOptions) {
    this.path = options.messagesPath;
    this.intervalMs = options.intervalMs ?? PERSIST_INTERVAL_MS;
    this.writeImpl =
      options.writeImpl ?? ((p, contents) => writeFile(p, contents));
  }

  get messagesPath(): string | null {
    return this.path;
  }

  /** Latest unpersisted snapshot, or null once a debounced write flushed it. */
  get latest(): ModelMessage[] | null {
    return this.pending;
  }

  setLatest(messages: ModelMessage[]): void {
    this.pending = messages;
  }

  /** True once the interrupted-step snapshot is safely on disk. */
  get syntheticsPersisted(): boolean {
    return this.syntheticsWritten;
  }

  markSyntheticsPersisted(): void {
    this.syntheticsWritten = true;
  }

  /**
   * Debounced persistence: avoid blocking the event loop with
   * JSON.stringify on every step when many agents run concurrently.
   */
  schedulePersist(): void {
    if (this.persistTimer) return;
    this.persistTimer = setTimeout(() => {
      this.persistTimer = null;
      const toWrite = this.pending;
      if (!toWrite) return;
      void this.enqueueWrite(toWrite)
        .then(() => {
          if (this.pending === toWrite) this.pending = null;
        })
        .catch(() => {});
    }, this.intervalMs);
  }

  /** Cancels a pending debounce; already-started writes remain in the queue. */
  cancelTimer(): void {
    if (this.persistTimer) {
      clearTimeout(this.persistTimer);
      this.persistTimer = null;
    }
  }

  /**
   * Serialized write: enqueued writes execute in order and never interleave.
   * A failed write rejects to its caller but does not poison the queue.
   */
  async enqueueWrite(messages: ModelMessage[]): Promise<void> {
    const path = this.path;
    if (!path) return;

    const contents = JSON.stringify(messages);
    const write = this.tail.then(() => this.writeImpl(path, contents));
    this.tail = write.catch(() => {});
    await write;
  }

  /** Resolves once every already-enqueued write has settled. */
  async waitForPendingWrites(): Promise<void> {
    let pending: Promise<void>;
    do {
      pending = this.tail;
      await pending;
    } while (pending !== this.tail);
  }
}
