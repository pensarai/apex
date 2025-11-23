import type { ModelMessage } from "ai";
import type { Session } from "../agent/sessions";
import fs from "fs";
import { z } from 'zod';

// TODO: create zod object and parse messages

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

const ModelMessageObject = z.discriminatedUnion('role', [
  SystemModelMessageObject,
  UserModelMessageObject,
  AssistantModelMessageObject,
  ToolMessageObject
]);


export interface ToolMessage {
  role: "tool";
  status: "pending" | "completed";
  toolCallId: string;
  content: string;
  args: Record<string, any>;
  toolName: string;
  createdAt: Date;
}

// export type Message = (ModelMessage & { createdAt: Date }) | ToolMessage;

export type Message = z.infer<typeof ModelMessageObject>;

export function getMessages(session: Session): Message[] {
  const messages = fs.readFileSync(session.rootPath + "/messages.json", "utf8");
  return ModelMessageObject.array().parse(JSON.parse(messages));
}

export function saveMessages(session: Session, messages: Message[]) {
  fs.writeFileSync(
    session.rootPath + "/messages.json",
    JSON.stringify(messages, null, 2)
  );
}

export function saveSubagentMessages(
  orchestratorSession: Session,
  subagentId: string,
  messages: Message[]
) {
  const subagentDir = `${orchestratorSession.rootPath}/subagents/${subagentId}`;

  // Create subagents directory if it doesn't exist
  if (!fs.existsSync(`${orchestratorSession.rootPath}/subagents`)) {
    fs.mkdirSync(`${orchestratorSession.rootPath}/subagents`, {
      recursive: true,
    });
  }

  // Create subagent-specific directory if it doesn't exist
  if (!fs.existsSync(subagentDir)) {
    fs.mkdirSync(subagentDir, { recursive: true });
  }

  // Save messages
  fs.writeFileSync(
    `${subagentDir}/messages.json`,
    JSON.stringify(messages, null, 2)
  );
}
