import z from "zod";
import {
  type EventID,
  type MessageID,
  MessageIDSchema,
  type NodeID,
  NodeIDSchema,
  type PartID,
  PartIDSchema,
  type SessionID,
  SessionIDSchema,
} from "./ids.ts";

// ─── Sub-shapes ─────────────────────────────────────────────────────────

export const NodeKindSchema = z.enum(["agent", "workflow", "tool_call"]);
export type NodeKind = z.infer<typeof NodeKindSchema>;

export const NodeStateSchema = z.enum([
  "pending",
  "running",
  "completed",
  "failed",
  "cancelled",
]);
export type NodeState = z.infer<typeof NodeStateSchema>;

export const MessageRoleSchema = z.enum([
  "system",
  "user",
  "assistant",
  "tool",
]);
export type MessageRole = z.infer<typeof MessageRoleSchema>;

export const AgentNodeSchema = z.object({
  id: NodeIDSchema,
  sessionId: SessionIDSchema,
  parentId: NodeIDSchema.nullable(),
  parentToolCallId: z.string().nullable(),
  sequence: z.number().int().nonnegative(),
  kind: NodeKindSchema,
  state: NodeStateSchema,
  name: z.string().nullable(),
  payload: z.record(z.string(), z.unknown()).default({}),
  createdAt: z.string(),
});
export type AgentNode = z.infer<typeof AgentNodeSchema>;

export const PartSchema = z.discriminatedUnion("type", [
  z.object({
    id: PartIDSchema,
    type: z.literal("text"),
    messageId: MessageIDSchema,
    sequence: z.number().int().nonnegative(),
    content: z.object({ text: z.string() }),
  }),
  z.object({
    id: PartIDSchema,
    type: z.literal("reasoning"),
    messageId: MessageIDSchema,
    sequence: z.number().int().nonnegative(),
    content: z.object({ text: z.string() }),
  }),
  z.object({
    id: PartIDSchema,
    type: z.literal("tool-call"),
    messageId: MessageIDSchema,
    sequence: z.number().int().nonnegative(),
    content: z.object({
      toolCallId: z.string(),
      toolName: z.string(),
      args: z.unknown(),
    }),
  }),
  z.object({
    id: PartIDSchema,
    type: z.literal("tool-result"),
    messageId: MessageIDSchema,
    sequence: z.number().int().nonnegative(),
    content: z.object({
      toolCallId: z.string(),
      result: z.unknown(),
      isError: z.boolean().optional(),
    }),
  }),
  z.object({
    id: PartIDSchema,
    type: z.literal("image"),
    messageId: MessageIDSchema,
    sequence: z.number().int().nonnegative(),
    content: z.object({
      url: z.string().optional(),
      mimeType: z.string().optional(),
      data: z.string().optional(),
    }),
  }),
  z.object({
    id: PartIDSchema,
    type: z.literal("file"),
    messageId: MessageIDSchema,
    sequence: z.number().int().nonnegative(),
    content: z.object({
      url: z.string().optional(),
      mimeType: z.string().optional(),
      data: z.string().optional(),
      name: z.string().optional(),
    }),
  }),
  z.object({
    id: PartIDSchema,
    type: z.literal("source"),
    messageId: MessageIDSchema,
    sequence: z.number().int().nonnegative(),
    content: z.object({
      url: z.string(),
      title: z.string().optional(),
      excerpt: z.string().optional(),
    }),
  }),
  z.object({
    id: PartIDSchema,
    type: z.literal("step-start"),
    messageId: MessageIDSchema,
    sequence: z.number().int().nonnegative(),
    content: z.object({}),
  }),
  z.object({
    id: PartIDSchema,
    type: z.literal("step-finish"),
    messageId: MessageIDSchema,
    sequence: z.number().int().nonnegative(),
    content: z.object({ finishReason: z.string().optional() }),
  }),
  z.object({
    id: PartIDSchema,
    type: z.literal("command-output"),
    messageId: MessageIDSchema,
    sequence: z.number().int().nonnegative(),
    content: z.object({ data: z.string() }),
  }),
  z.object({
    id: PartIDSchema,
    type: z.literal("error"),
    messageId: MessageIDSchema,
    sequence: z.number().int().nonnegative(),
    content: z.object({ message: z.string(), details: z.unknown().optional() }),
  }),
  z.object({
    id: PartIDSchema,
    type: z.literal("usage"),
    messageId: MessageIDSchema,
    sequence: z.number().int().nonnegative(),
    content: z.object({
      model: z.string(),
      inputTokens: z.number().int().nonnegative(),
      outputTokens: z.number().int().nonnegative(),
      totalCost: z.number().nonnegative().optional(),
    }),
  }),
]);
export type Part = z.infer<typeof PartSchema>;

export const TokenCountsSchema = z.object({
  inputTokens: z.number().int().nonnegative(),
  outputTokens: z.number().int().nonnegative(),
});
export type TokenCounts = z.infer<typeof TokenCountsSchema>;

export const MessageSchema = z.object({
  id: MessageIDSchema,
  nodeId: NodeIDSchema,
  sessionId: SessionIDSchema,
  role: MessageRoleSchema,
  sequence: z.number().int().nonnegative(),
  createdAt: z.string(),
});
export type Message = z.infer<typeof MessageSchema>;

// ─── ApexMessage union ──────────────────────────────────────────────────

const baseDurable = {
  sequence: z.number().int().nonnegative(),
  timestamp: z.string(),
};

export const ApexMessageSchema = z.discriminatedUnion("type", [
  // Node lifecycle (durable)
  z.object({
    type: z.literal("node.created"),
    node: AgentNodeSchema,
    ...baseDurable,
  }),
  z.object({
    type: z.literal("node.state"),
    nodeId: NodeIDSchema,
    state: NodeStateSchema,
    reason: z.string().optional(),
    ...baseDurable,
  }),
  z.object({
    type: z.literal("node.completed"),
    nodeId: NodeIDSchema,
    result: z.unknown().optional(),
    errorMessage: z.string().optional(),
    ...baseDurable,
  }),

  // Message + parts (durable)
  z.object({
    type: z.literal("message.created"),
    message: MessageSchema,
    parts: z.array(PartSchema),
    ...baseDurable,
  }),
  z.object({
    type: z.literal("part.added"),
    part: PartSchema,
    ...baseDurable,
  }),
  z.object({
    type: z.literal("part.updated"),
    partId: PartIDSchema,
    messageId: MessageIDSchema,
    patch: z.record(z.string(), z.unknown()),
    ...baseDurable,
  }),

  // Usage / cost (durable)
  z.object({
    type: z.literal("usage.recorded"),
    nodeId: NodeIDSchema,
    model: z.string(),
    tokens: TokenCountsSchema,
    cost: z.number().nonnegative().optional(),
    ...baseDurable,
  }),

  // Step boundary (durable)
  z.object({
    type: z.literal("step.finished"),
    nodeId: NodeIDSchema,
    finishReason: z.string().optional(),
    ...baseDurable,
  }),

  // Transient (never persisted)
  z.object({
    type: z.literal("text.delta"),
    messageId: MessageIDSchema,
    partId: PartIDSchema,
    delta: z.string(),
  }),
  z.object({
    type: z.literal("tool.input.delta"),
    nodeId: NodeIDSchema,
    argsTextDelta: z.string(),
  }),
  z.object({
    type: z.literal("command.output"),
    nodeId: NodeIDSchema,
    data: z.string(),
  }),
  z.object({
    type: z.literal("error"),
    nodeId: NodeIDSchema.optional(),
    error: z.object({
      message: z.string(),
      details: z.unknown().optional(),
    }),
  }),

  // Stream terminator
  z.object({
    type: z.literal("done"),
    sessionId: SessionIDSchema,
    result: z.unknown().optional(),
  }),
]);

export type ApexMessage = z.infer<typeof ApexMessageSchema>;

/** True for variants that should be persisted to the agent_events log. */
export const isDurableMessage = (msg: ApexMessage): boolean => {
  switch (msg.type) {
    case "node.created":
    case "node.state":
    case "node.completed":
    case "message.created":
    case "part.added":
    case "part.updated":
    case "usage.recorded":
    case "step.finished":
      return true;
    case "text.delta":
    case "tool.input.delta":
    case "command.output":
    case "error":
    case "done":
      return false;
  }
};

// Re-export ID types for convenience.
export type { EventID, MessageID, NodeID, PartID, SessionID };
