import { z } from "zod";
import { MessageIdSchema, PartIdSchema, SessionIdSchema } from "./ids";

const partBase = z.object({
  id: PartIdSchema,
  sessionId: SessionIdSchema,
  messageId: MessageIdSchema,
  index: z.number().int().nonnegative(),
});

export const TextPartSchema = partBase.extend({
  type: z.literal("text"),
  text: z.string(),
});

export const ReasoningPartSchema = partBase.extend({
  type: z.literal("reasoning"),
  text: z.string(),
  redacted: z.boolean().optional(),
});

export const FilePartSchema = partBase.extend({
  type: z.literal("file"),
  mimeType: z.string(),
  url: z.string().optional(),
  s3Key: z.string().optional(),
  filename: z.string().optional(),
});

export const ToolPartSchema = partBase.extend({
  type: z.literal("tool"),
  toolName: z.string(),
  nodeId: z.string(),
  externalToolCallId: z.string().optional(),
  state: z.enum(["pending", "running", "completed", "error"]),
  args: z.unknown().optional(),
  result: z.unknown().optional(),
  errorMessage: z.string().optional(),
});

export const StepStartPartSchema = partBase.extend({
  type: z.literal("step-start"),
});

export const StepFinishPartSchema = partBase.extend({
  type: z.literal("step-finish"),
  finishReason: z.string().optional(),
});

export const SnapshotPartSchema = partBase.extend({
  type: z.literal("snapshot"),
  label: z.string().optional(),
  s3Key: z.string().optional(),
});

export const PatchPartSchema = partBase.extend({
  type: z.literal("patch"),
  filePath: z.string(),
  diff: z.string(),
});

export const AgentPartSchema = partBase.extend({
  type: z.literal("agent"),
  childNodeId: z.string(),
  name: z.string().optional(),
  status: z.enum(["pending", "running", "completed", "error"]).optional(),
});

export const SubtaskPartSchema = partBase.extend({
  type: z.literal("subtask"),
  description: z.string(),
  status: z.enum(["pending", "running", "completed", "error"]).optional(),
});

export const RetryPartSchema = partBase.extend({
  type: z.literal("retry"),
  attempt: z.number().int().positive(),
  reason: z.string().optional(),
});

export const CompactionPartSchema = partBase.extend({
  type: z.literal("compaction"),
  messagesCompacted: z.number().int().positive(),
  summary: z.string(),
});

export const PartSchema = z.discriminatedUnion("type", [
  TextPartSchema,
  ReasoningPartSchema,
  FilePartSchema,
  ToolPartSchema,
  StepStartPartSchema,
  StepFinishPartSchema,
  SnapshotPartSchema,
  PatchPartSchema,
  AgentPartSchema,
  SubtaskPartSchema,
  RetryPartSchema,
  CompactionPartSchema,
]);

export type Part = z.infer<typeof PartSchema>;
export type PartType = Part["type"];
