import { existsSync, readFileSync } from "node:fs";
import type { ModelMessage } from "ai";
import type { AgentEventBus } from "../../eventBus";
import {
  buildInterruptedStepMessages,
  buildSyntheticToolResults,
} from "./interruptedStepMessages";
import type { AgentMessageWriter } from "./messagePersistence";
import type { ToolRecoverySnapshot } from "./toolLifecycle";

// ---------------------------------------------------------------------------
// Interrupted-step finalization — one operation that closes an interrupted
// step: synthetic results for every open call are emitted and persisted, the
// transcript is reconstructed so resumed sessions see valid tool-call/result
// pairs, and the write completes before the operation reports settled.
//
// Invariants:
// - a throwing listener never prevents persistence (its error is rethrown
//   only after the write has been attempted)
// - every open tool receives a synthetic result
// - a failed snapshot write leaves `syntheticsPersisted` false so onFinish
//   still attempts a write
// ---------------------------------------------------------------------------

export interface InterruptedStepFinalizerDeps {
  eventBus: AgentEventBus;
  sessionId: string;
  subagentId?: string;
  writer: AgentMessageWriter;
  responseToolName: string;
  responseToolFired: () => boolean;
  /** Read the persisted base from disk, or null when unavailable. */
  readBaseFromDisk?: () => ModelMessage[] | null;
  /** Opt-in debug sink for the response-tool tracer lines. */
  debugLog?: (message: string) => void;
}

export interface FinalizeInterruptedStepInput {
  snapshot: ToolRecoverySnapshot;
  reason: string;
  partIdFor?: (toolCallId: string) => string;
  messageId?: string;
}

export function createInterruptedStepFinalizer(
  deps: InterruptedStepFinalizerDeps,
): (input: FinalizeInterruptedStepInput) => Promise<void> {
  const debug = deps.debugLog;

  const readBaseFromDisk =
    deps.readBaseFromDisk ??
    (() => {
      const path = deps.writer.messagesPath;
      if (!path || !existsSync(path)) return null;
      try {
        return JSON.parse(readFileSync(path, "utf-8")) as ModelMessage[];
      } catch {
        // Corrupt file → proceed with empty base.
        return null;
      }
    });

  return async (input) => {
    const { snapshot, reason } = input;
    const { inFlightTools, completedResults, streamedArgText } = snapshot;

    const syntheticParts = buildSyntheticToolResults({
      inFlightTools,
      reason,
      responseToolName: deps.responseToolName,
      responseSubmitted: deps.responseToolFired(),
    });
    let emissionError: unknown;
    let hasEmissionError = false;

    if (debug) {
      const responseInFlight = [...inFlightTools.entries()].filter(
        ([, n]) => n === deps.responseToolName,
      );
      if (responseInFlight.length > 0) {
        debug(
          `[response-debug] emitSyntheticToolResults closing ${responseInFlight.length} response call(s) ` +
            `ids=${responseInFlight.map(([id]) => id).join(",")} reason="${reason}" ` +
            `responseToolFired=${deps.responseToolFired()}`,
        );
      }
    }

    for (const part of syntheticParts) {
      try {
        deps.eventBus.emit("tool-result", {
          toolCallId: part.toolCallId,
          toolName: part.toolName,
          result: part.output,
          // Canonical session id, not just the legacy subagentId alias, so the translator routes to THIS subagent's session.
          sessionId: deps.sessionId,
          subagentId: deps.subagentId,
          partId: input.partIdFor?.(part.toolCallId),
          messageId: input.messageId,
        });
      } catch (error) {
        if (!hasEmissionError) {
          emissionError = error;
          hasEmissionError = true;
        }
      }
    }

    if (!deps.writer.messagesPath) {
      if (hasEmissionError) throw emissionError;
      return;
    }

    // Cancel an unfired debounce and drain writes that already started.
    deps.writer.cancelTimer();
    await deps.writer.waitForPendingWrites();

    // Fall back to the on-disk snapshot once the debounced timer has flushed
    // the latest snapshot, so we don't overwrite history.
    let base: ModelMessage[] = deps.writer.latest ?? [];
    if (base.length === 0) {
      base = readBaseFromDisk() ?? [];
    }

    const { appended, needsStepReconstruction } = buildInterruptedStepMessages({
      base,
      inFlightTools,
      completedResults,
      syntheticParts,
      streamedArgText,
    });
    if (needsStepReconstruction && debug) {
      const responseReconstructed = [
        ...inFlightTools,
        ...completedResults.map((r) => [r.toolCallId, r.toolName] as const),
      ]
        .filter(([, n]) => n === deps.responseToolName)
        .map(([id]) => id);
      if (responseReconstructed.length > 0) {
        debug(
          `[response-debug] step-reconstruction for response call(s) ` +
            `ids=${responseReconstructed.join(",")} ` +
            `preservedArgChars=${responseReconstructed
              .map((id) => streamedArgText?.get(id)?.length ?? 0)
              .join(",")}`,
        );
      }
    }

    const next: ModelMessage[] = [...base, ...appended];
    deps.writer.setLatest(next);
    try {
      await deps.writer.enqueueWrite(next);
      // Only suppress onFinish's write once the snapshot is safely on disk.
      deps.writer.markSyntheticsPersisted();
    } catch {
      // Write failed — leave the flag false so onFinish still attempts a write.
    }

    if (hasEmissionError) throw emissionError;
  };
}
