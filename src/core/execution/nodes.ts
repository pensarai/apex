import { z } from "zod";
import { NodeIdSchema, SessionIdSchema } from "./ids";

export const NodeStateSchema = z.enum([
  "pending",
  "running",
  "completed",
  "error",
]);
export type NodeState = z.infer<typeof NodeStateSchema>;

const nodeBase = z.object({
  id: NodeIdSchema,
  sessionId: SessionIdSchema,
  parentId: NodeIdSchema.nullable(),
  parentToolCallId: NodeIdSchema.nullable(),
  name: z.string(),
  state: NodeStateSchema,
  sequence: z.number().int().nonnegative(),
  timeStarted: z.string().datetime().nullable(),
  timeCompleted: z.string().datetime().nullable(),
});

export const AgentNodeSchema = nodeBase.extend({
  kind: z.literal("agent"),
  payload: z.object({
    role: z.string().optional(),
    input: z.unknown().optional(),
    model: z.string().optional(),
    output: z.unknown().optional(),
    errorMessage: z.string().optional(),
  }),
});

export const WorkflowNodeSchema = nodeBase.extend({
  kind: z.literal("workflow"),
  payload: z.object({
    workflow: z.string(),
    phase: z.string().optional(),
    input: z.unknown().optional(),
    summary: z.unknown().optional(),
    errorMessage: z.string().optional(),
  }),
});

export const ToolCallNodeSchema = nodeBase.extend({
  kind: z.literal("tool_call"),
  payload: z.object({
    toolName: z.string(),
    externalToolCallId: z.string().optional(),
    args: z.unknown().optional(),
    result: z.unknown().optional(),
    errorMessage: z.string().optional(),
  }),
});

export const AgentNodeUnionSchema = z.discriminatedUnion("kind", [
  AgentNodeSchema,
  WorkflowNodeSchema,
  ToolCallNodeSchema,
]);

export type AgentNode = z.infer<typeof AgentNodeUnionSchema>;
export type AgentKindNode = z.infer<typeof AgentNodeSchema>;
export type WorkflowKindNode = z.infer<typeof WorkflowNodeSchema>;
export type ToolCallKindNode = z.infer<typeof ToolCallNodeSchema>;
export type NodeKind = AgentNode["kind"];
