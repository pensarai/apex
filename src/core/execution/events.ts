import { z } from "zod";
import {
  EventIdSchema,
  MessageIdSchema,
  NodeIdSchema,
  PartIdSchema,
  SessionIdSchema,
} from "./ids";
import { MessageSchema } from "./messages";
import { AgentNodeUnionSchema, NodeStateSchema } from "./nodes";
import { PartSchema } from "./parts";

const eventBase = z.object({
  id: EventIdSchema,
  sessionId: SessionIdSchema,
  sequence: z.number().int().nonnegative(),
  emitterNodeId: NodeIdSchema.nullable(),
  timestamp: z.string().datetime(),
});

export const NodeCreatedEventSchema = eventBase.extend({
  type: z.literal("node.created"),
  channel: z.literal("durable"),
  node: AgentNodeUnionSchema,
});

export const NodeStateChangedEventSchema = eventBase.extend({
  type: z.literal("node.state_changed"),
  channel: z.literal("durable"),
  nodeId: NodeIdSchema,
  state: NodeStateSchema,
  reason: z.string().optional(),
});

export const NodeCompletedEventSchema = eventBase.extend({
  type: z.literal("node.completed"),
  channel: z.literal("durable"),
  nodeId: NodeIdSchema,
  result: z.unknown().optional(),
  errorMessage: z.string().optional(),
});

export const MessageCreatedEventSchema = eventBase.extend({
  type: z.literal("message.created"),
  channel: z.literal("durable"),
  message: MessageSchema,
  parts: z.array(PartSchema).default([]),
});

export const PartAddedEventSchema = eventBase.extend({
  type: z.literal("part.added"),
  channel: z.literal("durable"),
  part: PartSchema,
});

export const PartUpdatedEventSchema = eventBase.extend({
  type: z.literal("part.updated"),
  channel: z.literal("durable"),
  partId: PartIdSchema,
  messageId: MessageIdSchema,
  patch: z.record(z.string(), z.unknown()),
});

export const StepFinishedEventSchema = eventBase.extend({
  type: z.literal("step.finished"),
  channel: z.literal("durable"),
  nodeId: NodeIdSchema,
  messageId: MessageIdSchema.optional(),
  finishReason: z.string().optional(),
});

export const UsageRecordedEventSchema = eventBase.extend({
  type: z.literal("usage.recorded"),
  channel: z.literal("durable"),
  nodeId: NodeIdSchema,
  model: z.string(),
  tokensInput: z.number().int().nonnegative(),
  tokensOutput: z.number().int().nonnegative(),
  tokensReasoning: z.number().int().nonnegative().optional(),
  tokensCacheRead: z.number().int().nonnegative().optional(),
  tokensCacheWrite: z.number().int().nonnegative().optional(),
  cost: z.number().nonnegative().optional(),
});

export const TextDeltaEventSchema = eventBase.extend({
  type: z.literal("text.delta"),
  channel: z.literal("transient"),
  messageId: MessageIdSchema,
  partId: PartIdSchema,
  delta: z.string(),
});

export const ToolInputDeltaEventSchema = eventBase.extend({
  type: z.literal("tool.input.delta"),
  channel: z.literal("transient"),
  nodeId: NodeIdSchema,
  externalToolCallId: z.string().optional(),
  argsTextDelta: z.string(),
});

export const CommandOutputEventSchema = eventBase.extend({
  type: z.literal("command.output"),
  channel: z.literal("transient"),
  nodeId: NodeIdSchema,
  data: z.string(),
});

export const DurableAgentEventSchema = z.discriminatedUnion("type", [
  NodeCreatedEventSchema,
  NodeStateChangedEventSchema,
  NodeCompletedEventSchema,
  MessageCreatedEventSchema,
  PartAddedEventSchema,
  PartUpdatedEventSchema,
  StepFinishedEventSchema,
  UsageRecordedEventSchema,
]);

export const TransientAgentEventSchema = z.discriminatedUnion("type", [
  TextDeltaEventSchema,
  ToolInputDeltaEventSchema,
  CommandOutputEventSchema,
]);

export const AgentExecutionEventSchema = z.union([
  DurableAgentEventSchema,
  TransientAgentEventSchema,
]);

export type DurableAgentEvent = z.infer<typeof DurableAgentEventSchema>;
export type TransientAgentEvent = z.infer<typeof TransientAgentEventSchema>;
export type AgentExecutionEvent = z.infer<typeof AgentExecutionEventSchema>;
export type AgentExecutionEventType = AgentExecutionEvent["type"];

export function isDurable(
  event: AgentExecutionEvent,
): event is DurableAgentEvent {
  return event.channel === "durable";
}

export function isTransient(
  event: AgentExecutionEvent,
): event is TransientAgentEvent {
  return event.channel === "transient";
}
