import type { ContextStore } from "./runContext";
import type { RecordedApproval, RunControlRecord } from "./runControlStore";
import type { RunRecord } from "./runStore";

/** The canonical committed context, as returned by ContextStore.getContext. */
export type RunContextSnapshot = NonNullable<
  Awaited<ReturnType<ContextStore["getContext"]>>
>;

/**
 * One internally-consistent read of a run's durable state, taken in a single
 * SQLite read transaction. Nulls mean "absent"; corruption throws instead.
 */
export interface RunObservation {
  record: RunRecord | null;
  context: RunContextSnapshot | null;
  control: RunControlRecord | null;
  approvals: RecordedApproval[];
}

/** Store surface for clients that observe without holding the execution lock. */
export interface RunObservationStore {
  observe(runId: string): Promise<RunObservation>;
}
