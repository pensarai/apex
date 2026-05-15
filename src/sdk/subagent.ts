import { mintNodeID, type NodeID, type SessionID } from "./ids.ts";
import type { ApexMessage, NodeKind } from "./messages.ts";

export type SubagentSpawnInit = {
  /** Parent session — child shares the session, parent_id chain extends the node tree. */
  session: { id: SessionID; nextSequence: () => number };
  /** Parent node — child node gets `parentId` set to this. */
  parentNodeId: NodeID;
  /** Optional tool-call id that requested the spawn (carried as `parentToolCallId` on the node). */
  parentToolCallId?: string | null;
  /** Child node kind. Defaults to `agent`. */
  kind?: NodeKind;
  /** Display name for the child node (e.g. `"auth-agent"`, `"coding-agent-3"`). */
  name?: string | null;
};

export type SubagentRunFn = (ctx: {
  nodeId: NodeID;
  emit: (msg: ApexMessage) => void;
  signal: AbortSignal;
}) => Promise<unknown>;

/**
 * Subagent.spawn — replaces the five `AgentEventBus.attachChild` sites
 * referenced in the design doc. Mints a child `nod_xxx` ID, emits the
 * `node.created` message on the parent session's stream, and returns a
 * `Run` for the child.
 *
 * Used by `runAttackSurface`, `delegateAuth`, `threatModelGenerator`,
 * `spawnCodingAgent`, `spawnPentestSwarm` in Phases 5 and 7.
 */
export const Subagent = {
  spawn(
    init: SubagentSpawnInit,
    emitParent: (msg: ApexMessage) => void,
    run: SubagentRunFn,
  ): {
    nodeId: NodeID;
    promise: Promise<unknown>;
    abort: (reason?: unknown) => void;
  } {
    const nodeId = mintNodeID();
    const controller = new AbortController();
    const now = new Date().toISOString();

    emitParent({
      type: "node.created",
      node: {
        id: nodeId,
        sessionId: init.session.id,
        parentId: init.parentNodeId,
        parentToolCallId: init.parentToolCallId ?? null,
        sequence: init.session.nextSequence(),
        kind: init.kind ?? "agent",
        state: "running",
        name: init.name ?? null,
        payload: {},
        createdAt: now,
      },
      sequence: init.session.nextSequence(),
      timestamp: now,
    });

    const promise = run({
      nodeId,
      emit: emitParent,
      signal: controller.signal,
    }).then(
      (result) => {
        emitParent({
          type: "node.completed",
          nodeId,
          result,
          sequence: init.session.nextSequence(),
          timestamp: new Date().toISOString(),
        });
        return result;
      },
      (err: unknown) => {
        const errorMessage = err instanceof Error ? err.message : String(err);
        emitParent({
          type: "node.completed",
          nodeId,
          errorMessage,
          sequence: init.session.nextSequence(),
          timestamp: new Date().toISOString(),
        });
        throw err;
      },
    );

    return {
      nodeId,
      promise,
      abort: (reason?: unknown) => controller.abort(reason),
    };
  },
};
