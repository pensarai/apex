import { mintSessionID, type SessionID } from "./ids.ts";
import { SequenceCounter } from "./sequence.ts";

export type SessionScope =
  | "recon_job"
  | "scan"
  | "sandbox_test_job"
  | "credential_test"
  | "threat_model"
  | "patching"
  | "other";

export type SessionInit = {
  id?: SessionID;
  parentSessionId?: SessionID | null;
  scope?: SessionScope;
  label?: string | null;
};

/**
 * In-memory representation of an agent execution session.
 * The DB row in `agent_sessions` is its durable projection — see persister.
 *
 * `fork()` and `resume()` (S9 in design doc) are deferred to a follow-up;
 * this prototype exposes only the create-and-stream path.
 */
export class Session {
  readonly id: SessionID;
  readonly parentSessionId: SessionID | null;
  readonly scope: SessionScope;
  readonly label: string | null;
  readonly createdAt: string;
  readonly sequence: SequenceCounter;

  constructor(init: SessionInit = {}) {
    this.id = init.id ?? mintSessionID();
    this.parentSessionId = init.parentSessionId ?? null;
    this.scope = init.scope ?? "other";
    this.label = init.label ?? null;
    this.createdAt = new Date().toISOString();
    this.sequence = new SequenceCounter();
  }

  nextSequence(): number {
    return this.sequence.next(this.id);
  }
}
