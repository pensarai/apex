import { z } from "zod";
import { MessageIdSchema, NodeIdSchema, SessionIdSchema } from "./ids";

export const MessageRoleSchema = z.enum(["user", "assistant", "system"]);
export type MessageRole = z.infer<typeof MessageRoleSchema>;

export const MessageSchema = z.object({
  id: MessageIdSchema,
  sessionId: SessionIdSchema,
  nodeId: NodeIdSchema,
  role: MessageRoleSchema,
  timeCreated: z.string().datetime(),
  metadata: z
    .object({
      model: z.string().optional(),
      finishReason: z.string().optional(),
      tokensInput: z.number().int().nonnegative().optional(),
      tokensOutput: z.number().int().nonnegative().optional(),
      tokensReasoning: z.number().int().nonnegative().optional(),
      tokensCacheRead: z.number().int().nonnegative().optional(),
      tokensCacheWrite: z.number().int().nonnegative().optional(),
    })
    .partial()
    .optional(),
});

export type Message = z.infer<typeof MessageSchema>;
