import type { ToolResultPart } from "ai";
import { responseArgBytes } from "./streamDiagnostics";

// ---------------------------------------------------------------------------
// Tool lifecycle tracker — owns the per-stream view of tool-call state:
// in-flight calls, completed-but-unpersisted results, streamed argument text,
// and deferred tool errors. Purely stateful; event emission, persistence,
// and disposal live elsewhere.
// ---------------------------------------------------------------------------

export interface TrackedToolError {
  message: string;
  input: unknown;
  toolName: string;
}

/** Immutable point-in-time view used by the interrupted-step finalization. */
export interface ToolRecoverySnapshot {
  readonly inFlightTools: ReadonlyMap<string, string>;
  readonly completedResults: readonly ToolResultPart[];
  readonly streamedArgText: ReadonlyMap<string, string>;
  readonly toolErrors: ReadonlyMap<string, TrackedToolError>;
}

/** Structural stream-part view the tracker observes. */
export interface LifecycleChunk {
  type: string;
  id?: string;
  toolCallId?: string;
  toolName?: string;
  delta?: string;
  input?: unknown;
  error?: unknown;
  result?: unknown;
  output?: unknown;
}

export class ToolLifecycleTracker {
  private readonly inFlight = new Map<string, string>();
  private readonly completed: ToolResultPart[] = [];
  private readonly streamedArgs = new Map<string, string>();
  private readonly errors = new Map<string, TrackedToolError>();

  /** Update tracker state from one stream part. */
  observePart(chunk: LifecycleChunk): void {
    switch (chunk.type) {
      case "tool-input-start":
        // Track from the start so a truncated call still gets closed instead of left "running".
        this.inFlight.set(chunk.id as string, chunk.toolName as string);
        this.streamedArgs.set(chunk.id as string, "");
        break;
      case "tool-input-delta":
        this.streamedArgs.set(
          chunk.id as string,
          (this.streamedArgs.get(chunk.id as string) ?? "") +
            (chunk.delta ?? ""),
        );
        break;
      case "tool-call":
        this.inFlight.set(chunk.toolCallId as string, chunk.toolName as string);
        break;
      case "tool-error": {
        // `execute` never runs for an errored call, so it must be cleared here or finish-step would fabricate a bogus "did not complete".
        const toolCallId = chunk.toolCallId as string;
        this.inFlight.delete(toolCallId);
        const errMsg =
          chunk.error instanceof Error
            ? chunk.error.message
            : typeof chunk.error === "string"
              ? chunk.error
              : (() => {
                  try {
                    return JSON.stringify(chunk.error);
                  } catch {
                    return String(chunk.error);
                  }
                })();
        const partialArgs =
          chunk.input !== undefined &&
          chunk.input !== null &&
          responseArgBytes(chunk.input) > 2
            ? chunk.input
            : (this.streamedArgs.get(toolCallId) ?? "");
        this.errors.set(toolCallId, {
          message: errMsg,
          input: partialArgs,
          toolName: chunk.toolName as string,
        });
        break;
      }
      case "tool-result":
        this.inFlight.delete(chunk.toolCallId as string);
        this.completed.push({
          type: "tool-result",
          toolCallId: chunk.toolCallId as string,
          toolName: chunk.toolName as string,
          output: (chunk.result ?? chunk.output) as ToolResultPart["output"],
        });
        break;
    }
  }

  /** finish-step: onStepFinish has persisted this step; drop its results so a later abort doesn't re-append them. */
  onStepPersisted(): void {
    this.completed.length = 0;
  }

  /**
   * Flush deferred tool errors into completed error-text results (the
   * interrupted-step path — they never reached a finish-step). Returns the
   * flushed entries so the caller can emit them; clears the error map.
   */
  flushToolErrorsToResults(): Array<
    [toolCallId: string, error: TrackedToolError]
  > {
    const flushed: Array<[string, TrackedToolError]> = [];
    for (const [toolCallId, info] of this.errors) {
      this.completed.push({
        type: "tool-result",
        toolCallId,
        toolName: info.toolName,
        output: {
          type: "error-text",
          value: `Tool call failed: ${info.message}`,
        },
      });
      flushed.push([toolCallId, info]);
    }
    this.errors.clear();
    return flushed;
  }

  clearToolErrors(): void {
    this.errors.clear();
  }

  clearInFlight(): void {
    this.inFlight.clear();
  }

  /** Whether an interrupted step has state worth persisting (open tools or unpersisted results). */
  hasUnpersistedState(): boolean {
    return this.inFlight.size > 0 || this.completed.length > 0;
  }

  get inFlightTools(): ReadonlyMap<string, string> {
    return this.inFlight;
  }

  get toolErrors(): ReadonlyMap<string, TrackedToolError> {
    return this.errors;
  }

  get completedResults(): readonly ToolResultPart[] {
    return this.completed;
  }

  get streamedArgText(): ReadonlyMap<string, string> {
    return this.streamedArgs;
  }

  /** Independent point-in-time copy; mutating it never affects the tracker. */
  snapshot(): ToolRecoverySnapshot {
    return {
      inFlightTools: new Map(this.inFlight),
      completedResults: this.completed.map((r) => ({ ...r })),
      streamedArgText: new Map(this.streamedArgs),
      toolErrors: new Map(this.errors),
    };
  }
}
