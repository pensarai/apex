import type { AgentEventBus, AgentEventMap } from "../eventBus";

export interface TraceLinkedEvidenceReference {
  description: string;
  toolCallId: string;
  toolName: string;
}

type ToolResultEvent = AgentEventMap["tool-result"];

export type PersistedEvidenceObservation = Pick<
  ToolResultEvent,
  "toolCallId" | "toolName" | "subagentId" | "sessionId"
> & {
  failed: boolean;
};

export interface FastStrikeEvidenceLedgerOptions {
  initialObservations?: readonly PersistedEvidenceObservation[];
  onObservation?: (observation: PersistedEvidenceObservation) => void;
}

function isErrorObservation(result: unknown): boolean {
  return (
    typeof result === "object" &&
    result !== null &&
    "type" in result &&
    result.type === "error-text"
  );
}

function observationScope(
  observation: PersistedEvidenceObservation,
): string | undefined {
  return observation.subagentId ?? observation.sessionId;
}

/** Verifies objective results against completed observations in the engagement trace. */
export class FastStrikeEvidenceLedger {
  private readonly observations = new Map<
    string,
    PersistedEvidenceObservation[]
  >();

  private record(observation: PersistedEvidenceObservation): void {
    const existing = this.observations.get(observation.toolCallId) ?? [];
    const duplicate = existing.some(
      (candidate) =>
        candidate.toolName === observation.toolName &&
        candidate.subagentId === observation.subagentId &&
        candidate.sessionId === observation.sessionId &&
        candidate.failed === observation.failed,
    );
    if (!duplicate) {
      existing.push(observation);
      this.observations.set(observation.toolCallId, existing);
    }
  }

  private readonly onToolResult = (event: ToolResultEvent): void => {
    const observation: PersistedEvidenceObservation = {
      toolCallId: event.toolCallId,
      toolName: event.toolName,
      subagentId: event.subagentId,
      sessionId: event.sessionId,
      failed: isErrorObservation(event.result),
    };
    this.record(observation);
    this.options.onObservation?.(structuredClone(observation));
  };

  constructor(
    private readonly eventBus: AgentEventBus,
    private readonly options: FastStrikeEvidenceLedgerOptions = {},
  ) {
    for (const observation of options.initialObservations ?? []) {
      this.record(structuredClone(observation));
    }
    eventBus.on("tool-result", this.onToolResult);
  }

  validateEvidence(
    references: TraceLinkedEvidenceReference[] | undefined,
    allowedScopes: ReadonlySet<string>,
    required = false,
  ): string | undefined {
    if (!references?.length) {
      return required
        ? "An impact-proven result requires trace-linked evidence from a completed observation-producing tool call."
        : undefined;
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
        return `Evidence toolCallId "${reference.toolCallId}" belongs to "${observedNames}", not "${reference.toolName}".`;
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
        return `Evidence toolCallId "${reference.toolCallId}" is ambiguous across multiple execution scopes.`;
      }
    }

    return undefined;
  }

  dispose(): void {
    this.eventBus.off("tool-result", this.onToolResult);
  }

  validateImpactEvidence(
    references: TraceLinkedEvidenceReference[] | undefined,
    allowedScopes: ReadonlySet<string>,
  ): string | undefined {
    return this.validateEvidence(references, allowedScopes, true);
  }
}
