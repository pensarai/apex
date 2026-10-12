import type {
  ContextChange,
  ContextReference,
  ContextStore,
} from "./runContext";
import type { EvidenceReference } from "./runEvidence";
import type { RunStore } from "./runStore";

export interface SessionEvidence {
  rootPath: string;
  files: EvidenceReference[];
}

export interface RunCheckpointStore extends RunStore, ContextStore {
  commitContext(
    runId: string,
    attemptId: string,
    expectedRevision: number,
    change: ContextChange,
    evidence?: SessionEvidence,
  ): Promise<ContextReference>;
  getEvidence(runId: string): Promise<SessionEvidence | undefined>;
}
