import type { AgentEventBus, AgentEventMap } from "../eventBus";

export interface TraceLinkedEvidenceReference {
  description: string;
  toolCallId: string;
  toolName: string;
}

type ToolResultEvent = AgentEventMap["tool-result"];

type ToolObservation = Pick<
  ToolResultEvent,
  "toolCallId" | "toolName" | "subagentId" | "sessionId"
> & {
  failed: boolean;
};

function isErrorObservation(result: unknown): boolean {
  return (
    typeof result === "object" &&
    result !== null &&
    "type" in result &&
    result.type === "error-text"
  );
}

function observationScope(observation: ToolObservation): string | undefined {
  return observation.subagentId ?? observation.sessionId;
}

/**
 * Objective-scoped index of completed tool observations.
 *
 * Tool output remains in the normal trace/session stores. This ledger only
 * verifies the stable join keys supplied in a fast-strike result.
 */
export class FastStrikeEvidenceLedger {
  private readonly observations = new Map<string, ToolObservation[]>();

  private readonly onToolResult = (event: ToolResultEvent): void => {
    const observation: ToolObservation = {
      toolCallId: event.toolCallId,
      toolName: event.toolName,
      subagentId: event.subagentId,
      sessionId: event.sessionId,
      failed: isErrorObservation(event.result),
    };
    const existing = this.observations.get(observation.toolCallId) ?? [];
    existing.push(observation);
    this.observations.set(observation.toolCallId, existing);
  };

  constructor(private readonly eventBus: AgentEventBus) {
    eventBus.on("tool-result", this.onToolResult);
  }

  dispose(): void {
    this.eventBus.off("tool-result", this.onToolResult);
  }

  /** Return a model-facing correction when a claimed observation is absent. */
  validateImpactEvidence(
    references: TraceLinkedEvidenceReference[] | undefined,
    allowedScopes: ReadonlySet<string>,
  ): string | undefined {
    if (!references || references.length === 0) {
      return (
        "An impact-proven result requires at least one trace-linked evidence " +
        "reference from a completed observation-producing tool call."
      );
    }

    for (const reference of references) {
      const scoped = (this.observations.get(reference.toolCallId) ?? []).filter(
        (observation) => {
          const scope = observationScope(observation);
          return scope !== undefined && allowedScopes.has(scope);
        },
      );
      if (scoped.length === 0) {
        return `Evidence toolCallId "${reference.toolCallId}" was not observed in this execution scope.`;
      }

      const named = scoped.filter(
        (observation) => observation.toolName === reference.toolName,
      );
      if (named.length === 0) {
        const observedNames = [
          ...new Set(scoped.map((observation) => observation.toolName)),
        ].join(", ");
        return (
          `Evidence toolCallId "${reference.toolCallId}" belongs to ` +
          `"${observedNames}", not "${reference.toolName}".`
        );
      }
      if (reference.toolName === "response") {
        return "The terminal response tool is not an observation and cannot prove impact.";
      }
      if (named.every((observation) => observation.failed)) {
        return `Evidence toolCallId "${reference.toolCallId}" only produced an error result.`;
      }
      const successfulScopes = new Set(
        named
          .filter((observation) => !observation.failed)
          .map(observationScope),
      );
      if (successfulScopes.size > 1) {
        return (
          `Evidence toolCallId "${reference.toolCallId}" is ambiguous across ` +
          "multiple execution scopes; cite a unique observation."
        );
      }
    }

    return undefined;
  }
}
