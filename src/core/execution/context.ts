import type { AgentEventBus } from "../eventBus";
import type {
  AgentExecutionEvent,
  DurableAgentEvent,
  TransientAgentEvent,
} from "./events";
import {
  newEventId,
  newMessageId,
  newNodeId,
  newPartId,
  type MessageID,
  type NodeID,
  type PartID,
  type SessionID,
} from "./ids";
import type { Message, MessageRole } from "./messages";
import type { AgentNode, NodeKind, NodeState } from "./nodes";
import type { Part } from "./parts";
import { SequenceCounter } from "./sequence";

export interface RegisterNodeOptions {
  kind: NodeKind;
  name: string;
  parentNodeId?: NodeID | null;
  parentToolCallId?: NodeID | null;
  legacySubagentId?: string;
  externalToolCallId?: string;
  payload?: Record<string, unknown>;
  initialState?: NodeState;
}

export interface RecordMessageOptions {
  nodeId: NodeID;
  role: MessageRole;
  parts?: Omit<Part, "id" | "sessionId" | "messageId" | "index">[];
  metadata?: Message["metadata"];
}

export interface ExecutionContextOptions {
  sessionId: SessionID;
  bus: AgentEventBus;
  startingSequence?: number;
}

export class ExecutionContext {
  readonly sessionId: SessionID;
  private readonly bus: AgentEventBus;
  private readonly sequence: SequenceCounter;
  private readonly subagentToNode = new Map<string, NodeID>();
  private readonly externalToolCallToNode = new Map<string, NodeID>();
  private readonly parentByNode = new Map<NodeID, NodeID | null>();

  constructor(opts: ExecutionContextOptions) {
    this.sessionId = opts.sessionId;
    this.bus = opts.bus;
    this.sequence = new SequenceCounter();
    if (opts.startingSequence !== undefined) {
      this.sequence.seed(opts.sessionId, opts.startingSequence);
    }
  }

  resolveLegacySubagent(legacyId: string): NodeID | undefined {
    return this.subagentToNode.get(legacyId);
  }

  resolveExternalToolCall(externalId: string): NodeID | undefined {
    return this.externalToolCallToNode.get(externalId);
  }

  bindLegacySubagent(legacyId: string, nodeId: NodeID): void {
    this.subagentToNode.set(legacyId, nodeId);
  }

  bindExternalToolCall(externalId: string, nodeId: NodeID): void {
    this.externalToolCallToNode.set(externalId, nodeId);
  }

  parentOf(nodeId: NodeID): NodeID | null {
    return this.parentByNode.get(nodeId) ?? null;
  }

  registerNode(opts: RegisterNodeOptions): NodeID {
    const id = newNodeId();
    const sequence = this.sequence.next(this.sessionId);
    const parentId = opts.parentNodeId ?? null;
    const parentToolCallId = opts.parentToolCallId ?? null;
    const now = new Date().toISOString();
    const initialState: NodeState = opts.initialState ?? "pending";

    this.parentByNode.set(id, parentId);
    if (opts.legacySubagentId) {
      this.subagentToNode.set(opts.legacySubagentId, id);
    }
    if (opts.externalToolCallId) {
      this.externalToolCallToNode.set(opts.externalToolCallId, id);
    }

    const node = this.assembleNode({
      id,
      parentId,
      parentToolCallId,
      kind: opts.kind,
      name: opts.name,
      state: initialState,
      sequence,
      timeStarted: initialState === "pending" ? null : now,
      payload: opts.payload ?? {},
      externalToolCallId: opts.externalToolCallId,
    });

    this.emitDurable({
      id: newEventId(),
      sessionId: this.sessionId,
      sequence,
      emitterNodeId: parentId ?? id,
      timestamp: now,
      type: "node.created",
      channel: "durable",
      node,
    });

    return id;
  }

  transitionNode(nodeId: NodeID, state: NodeState, reason?: string): void {
    const sequence = this.sequence.next(this.sessionId);
    this.emitDurable({
      id: newEventId(),
      sessionId: this.sessionId,
      sequence,
      emitterNodeId: nodeId,
      timestamp: new Date().toISOString(),
      type: "node.state_changed",
      channel: "durable",
      nodeId,
      state,
      reason,
    });
  }

  completeNode(opts: {
    nodeId: NodeID;
    result?: unknown;
    errorMessage?: string;
  }): void {
    const sequence = this.sequence.next(this.sessionId);
    this.emitDurable({
      id: newEventId(),
      sessionId: this.sessionId,
      sequence,
      emitterNodeId: opts.nodeId,
      timestamp: new Date().toISOString(),
      type: "node.completed",
      channel: "durable",
      nodeId: opts.nodeId,
      result: opts.result,
      errorMessage: opts.errorMessage,
    });
  }

  recordMessage(opts: RecordMessageOptions): MessageID {
    const messageId = newMessageId();
    const sequence = this.sequence.next(this.sessionId);
    const timeCreated = new Date().toISOString();

    const parts: Part[] = (opts.parts ?? []).map((p, idx) =>
      this.assemblePart(messageId, idx, p),
    );

    const message: Message = {
      id: messageId,
      sessionId: this.sessionId,
      nodeId: opts.nodeId,
      role: opts.role,
      timeCreated,
      metadata: opts.metadata,
    };

    this.emitDurable({
      id: newEventId(),
      sessionId: this.sessionId,
      sequence,
      emitterNodeId: opts.nodeId,
      timestamp: timeCreated,
      type: "message.created",
      channel: "durable",
      message,
      parts,
    });

    return messageId;
  }

  addPart(
    messageId: MessageID,
    nodeId: NodeID,
    part: Omit<Part, "id" | "sessionId" | "messageId" | "index">,
    index: number,
  ): PartID {
    const partId = newPartId();
    const sequence = this.sequence.next(this.sessionId);
    const assembled = this.assemblePart(messageId, index, part, partId);
    this.emitDurable({
      id: newEventId(),
      sessionId: this.sessionId,
      sequence,
      emitterNodeId: nodeId,
      timestamp: new Date().toISOString(),
      type: "part.added",
      channel: "durable",
      part: assembled,
    });
    return partId;
  }

  recordUsage(opts: {
    nodeId: NodeID;
    model: string;
    tokensInput: number;
    tokensOutput: number;
    tokensReasoning?: number;
    tokensCacheRead?: number;
    tokensCacheWrite?: number;
    cost?: number;
  }): void {
    const sequence = this.sequence.next(this.sessionId);
    this.emitDurable({
      id: newEventId(),
      sessionId: this.sessionId,
      sequence,
      emitterNodeId: opts.nodeId,
      timestamp: new Date().toISOString(),
      type: "usage.recorded",
      channel: "durable",
      nodeId: opts.nodeId,
      model: opts.model,
      tokensInput: opts.tokensInput,
      tokensOutput: opts.tokensOutput,
      tokensReasoning: opts.tokensReasoning,
      tokensCacheRead: opts.tokensCacheRead,
      tokensCacheWrite: opts.tokensCacheWrite,
      cost: opts.cost,
    });
  }

  emitTextDelta(opts: {
    messageId: MessageID;
    partId: PartID;
    nodeId: NodeID;
    delta: string;
  }): void {
    const sequence = this.sequence.next(this.sessionId);
    this.emitTransient({
      id: newEventId(),
      sessionId: this.sessionId,
      sequence,
      emitterNodeId: opts.nodeId,
      timestamp: new Date().toISOString(),
      type: "text.delta",
      channel: "transient",
      messageId: opts.messageId,
      partId: opts.partId,
      delta: opts.delta,
    });
  }

  emitCommandOutput(nodeId: NodeID, data: string): void {
    const sequence = this.sequence.next(this.sessionId);
    this.emitTransient({
      id: newEventId(),
      sessionId: this.sessionId,
      sequence,
      emitterNodeId: nodeId,
      timestamp: new Date().toISOString(),
      type: "command.output",
      channel: "transient",
      nodeId,
      data,
    });
  }

  private emitDurable(event: DurableAgentEvent): void {
    this.bus.emitExecution(event satisfies AgentExecutionEvent);
  }

  private emitTransient(event: TransientAgentEvent): void {
    this.bus.emitExecution(event satisfies AgentExecutionEvent);
  }

  private assembleNode(opts: {
    id: NodeID;
    parentId: NodeID | null;
    parentToolCallId: NodeID | null;
    kind: NodeKind;
    name: string;
    state: NodeState;
    sequence: number;
    timeStarted: string | null;
    payload: Record<string, unknown>;
    externalToolCallId?: string;
  }): AgentNode {
    const base = {
      id: opts.id,
      sessionId: this.sessionId,
      parentId: opts.parentId,
      parentToolCallId: opts.parentToolCallId,
      name: opts.name,
      state: opts.state,
      sequence: opts.sequence,
      timeStarted: opts.timeStarted,
      timeCompleted: null,
    };
    if (opts.kind === "agent") {
      return { ...base, kind: "agent", payload: opts.payload };
    }
    if (opts.kind === "workflow") {
      return {
        ...base,
        kind: "workflow",
        payload: {
          workflow: String(opts.payload.workflow ?? opts.name),
          ...opts.payload,
        },
      };
    }
    return {
      ...base,
      kind: "tool_call",
      payload: {
        toolName: String(opts.payload.toolName ?? opts.name),
        externalToolCallId: opts.externalToolCallId,
        ...opts.payload,
      },
    };
  }

  private assemblePart(
    messageId: MessageID,
    index: number,
    part: Omit<Part, "id" | "sessionId" | "messageId" | "index">,
    explicitId?: PartID,
  ): Part {
    return {
      id: explicitId ?? newPartId(),
      sessionId: this.sessionId,
      messageId,
      index,
      ...part,
    } as Part;
  }
}
