import { mintNodeID, type NodeID, type SessionID } from "./ids.ts";
import type { ApexMessage, NodeKind } from "./messages.ts";

/**
 * The shape of the stream channel injected into apex tool context for
 * V2 ApexMessage emission. Defined here (rather than in
 * `core/agents/offSecAgent/tools/types.ts`) so SDK modules can refer to it
 * without depending on tool internals.
 */
export type ApexStreamChannel = {
  emit: (msg: ApexMessage) => void;
  session: { id: SessionID; nextSequence: () => number };
  parentNodeId: NodeID;
};

/**
 * Wrapper around the node.created/node.completed emit pattern used by every
 * `attachChild` spawn site (5 sites total). Reduces each call site to a few
 * lines and keeps the wire shape consistent.
 *
 * Usage:
 * ```ts
 * const spawned = beginSpawnedNode(ctx.apexStream, { name: "auth-agent" });
 * try {
 *   const result = await doWork();
 *   spawned.complete({ result });
 * } catch (err) {
 *   spawned.complete({ errorMessage: String(err) });
 * }
 * ```
 *
 * Safe to call with `undefined` stream — both create and complete become
 * no-ops, so callers don't need their own null checks.
 */
export function beginSpawnedNode(
  stream: ApexStreamChannel | undefined | null,
  init: {
    name: string;
    kind?: NodeKind;
    payload?: Record<string, unknown>;
  },
): {
  nodeId: NodeID | null;
  complete: (outcome: { result?: unknown; errorMessage?: string }) => void;
} {
  if (!stream) {
    return { nodeId: null, complete: () => undefined };
  }
  const nodeId = mintNodeID();
  const now = new Date().toISOString();
  stream.emit({
    type: "node.created",
    node: {
      id: nodeId,
      sessionId: stream.session.id,
      parentId: stream.parentNodeId,
      parentToolCallId: null,
      sequence: stream.session.nextSequence(),
      kind: init.kind ?? "agent",
      state: "running",
      name: init.name,
      payload: init.payload ?? {},
      createdAt: now,
    },
    sequence: stream.session.nextSequence(),
    timestamp: now,
  });

  return {
    nodeId,
    complete: (outcome) => {
      stream.emit({
        type: "node.completed",
        nodeId,
        result: outcome.result,
        errorMessage: outcome.errorMessage,
        sequence: stream.session.nextSequence(),
        timestamp: new Date().toISOString(),
      });
    },
  };
}
