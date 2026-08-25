import type { TraceRecord } from "../../../core/agents/offSecAgent";
import type { AgentEventBus } from "../../../core/eventBus";
import { attachWandbToEventBus } from "../../../core/integrations/wandb/upload";
import type { SessionInfo } from "../../../core/session";

type TraceEvent = {
  record: TraceRecord;
  subagentId?: string;
};

export type RunTraceOptions = {
  /** Generation guard — called on every trace-record; return false to drop it. */
  isCurrent: () => boolean;
  /** Accumulate deduped subagent step token usage. */
  recordTokenUsage: (
    inputTokens: number,
    outputTokens: number,
    cacheReadTokens: number,
    cacheWriteTokens: number,
  ) => void;
  /** Optional uploader override for tests; defaults to the real W&B attach. */
  attach?: (
    session: SessionInfo,
    eventBus: AgentEventBus,
  ) => Promise<(() => Promise<void>) | null>;
};

/**
 * Owns the W&B trace-upload lifecycle for a single agent run: buffers records
 * emitted before the uploader attaches (new sessions fire onSessionReady
 * mid-construction), dedupes subagent step tokens against the early-buffer
 * replay, and flushes on cleanup. Construct once per run; call `cleanup()` on
 * every exit path.
 */
export class RunTraceSession {
  private cleanup: (() => Promise<void>) | null = null;
  private earlyBuffer: TraceEvent[] | null = [];
  private readonly countedSubagentSteps = new Set<string>();
  private readonly earlyBufferHandler = (e: TraceEvent) => {
    this.earlyBuffer?.push(e);
  };

  constructor(
    private readonly eventBus: AgentEventBus,
    private readonly options: RunTraceOptions,
  ) {
    eventBus.on("trace-record", this.earlyBufferHandler);
    eventBus.on("trace-record", this.countSubagentStep);
  }

  /** Idempotent: only the first successful attach takes effect. */
  async tryAttach(session: SessionInfo): Promise<void> {
    if (this.cleanup) return;
    const attach = this.options.attach ?? attachWandbToEventBus;
    const cleanup = await attach(session, this.eventBus).catch((e: unknown) => {
      console.error("[wandb] Attach failed:", e);
      return null;
    });
    // Capture the buffer before detaching the early handler.
    const buffered = this.earlyBuffer;
    this.stopBuffering();
    if (cleanup) {
      this.cleanup = cleanup;
      // Replay records captured before the handler attached.
      if (buffered) {
        for (const e of buffered) this.eventBus.emit("trace-record", e);
      }
    }
  }

  /** Flush the uploader and detach all listeners. Safe to call repeatedly. */
  async cleanupRun(): Promise<void> {
    this.stopBuffering();
    this.eventBus.off("trace-record", this.countSubagentStep);
    if (this.cleanup) {
      const fn = this.cleanup;
      this.cleanup = null;
      await fn().catch((e: unknown) =>
        console.error("[wandb] Flush failed:", e),
      );
    }
  }

  private stopBuffering(): void {
    this.earlyBuffer = null;
    this.eventBus.off("trace-record", this.earlyBufferHandler);
  }

  // Subagent steps (orchestrator ones lack subagentId, counted elsewhere). The
  // key dedupes the W&B early-buffer replay.
  private countSubagentStep = (e: TraceEvent): void => {
    if (!this.options.isCurrent()) return;
    const { record, subagentId } = e;
    if (!subagentId || record.type !== "step") return;
    const key = `${subagentId}:${record.stepIndex}:${record.timestamp}`;
    if (this.countedSubagentSteps.has(key)) return;
    this.countedSubagentSteps.add(key);
    this.options.recordTokenUsage(
      record.usage.inputTokens,
      record.usage.outputTokens,
      record.usage.cacheReadTokens ?? 0,
      record.usage.cacheWriteTokens ?? 0,
    );
  };
}
