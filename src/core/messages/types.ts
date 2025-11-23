import { z } from 'zod';

const ToolMessageObject = z.object({
  role: z.literal('tool'),
  status: z.enum(['pending', 'completed']),
  toolCallId: z.string(),
  content: z.string(),
  args: z.record(z.string(), z.any()),
  toolName: z.string(),
  createdAt: z.coerce.date()
});

const SystemModelMessageObject = z.object({
  role: z.literal('system'),
  content: z.string(),
  createdAt: z.coerce.date(),
  providerOptions: z.record(z.string(), z.any()).optional()
});

const TextPartObject = z.object({
  type: z.literal('text'),
  text: z.string(),
  providerOptions: z.record(z.string(), z.any()).optional()
});

const FilePartObject = z.object({
  type: z.literal('file'),
  data: z.union([
    z.string(),
    z.instanceof(Uint8Array),
    z.instanceof(ArrayBuffer),
    z.instanceof(Buffer),
    z.url()
  ]),
  filename: z.string().optional(),
  mediaType: z.string(),
  providerOptions: z.record(z.string(), z.any()).optional()
});

const ReasoningPartObject = z.object({
  type: z.literal('reasoning'),
  text: z.string(),
  providerOptions: z.record(z.string(), z.any()).optional()
});

const ToolCallPartObject = z.object({
  type: z.literal('tool-call'),
  toolCallId: z.string(),
  toolName: z.string(),
  input: z.unknown(),
  providerOptions: z.record(z.string(), z.any()).optional(),
  providerExecuted: z.boolean().optional()
});


const ToolResultOutputObject = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('text'),
    value: z.string()
  }),
  z.object({
    type: z.literal('json'),
    value: z.any()
  }),
  z.object({
    type: z.literal('error-text'),
    value: z.string()
  }),
  z.object({
    type: z.literal('error-json'),
    value: z.any()
  }),
  z.object({
    type: z.literal('content'),
    value: z.array(
      z.discriminatedUnion('type', [
        z.object({
          type: z.literal('text'),
          text:  z.string()
        }),
        z.object({
          type: z.literal('media'),
          data: z.string(),
          mediaType: z.string()
        })
      ])
    )
  })
]);

const ToolResultPartObject = z.object({
  type: z.literal('tool-result'),
  toolCallId: z.string(),
  toolName: z.string(),
  output: ToolResultOutputObject,
  providerOptions: z.record(z.string(), z.any()).optional(),
});

const AssistantModelMessageObject = z.object({
  role: z.literal('assistant'),
  content: z.union([
    z.string(),
    z.array(
      z.discriminatedUnion('type', [
        TextPartObject,
        FilePartObject,
        ReasoningPartObject,
        ToolCallPartObject,
        ToolResultPartObject
      ])
    )
  ]),
  createdAt: z.coerce.date(),
  providerOptions: z.record(z.string(), z.any()).optional(),
});


const UserModelMessageObject = z.object({
  role: z.literal('user'),
  content: z.union([
    z.string(),
    z.array(
      z.discriminatedUnion('type', [ TextPartObject, FilePartObject ])
    )
  ]),
  createdAt: z.coerce.date(),
  providerOptions: z.record(z.string(), z.any()).optional(),
});

export const ModelMessageObject = z.discriminatedUnion('role', [
  SystemModelMessageObject,
  UserModelMessageObject,
  AssistantModelMessageObject,
  ToolMessageObject
]);

export type ToolMessage = z.infer<typeof ToolMessageObject>;