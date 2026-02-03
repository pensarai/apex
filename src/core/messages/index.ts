import fs from "fs";
import { nanoid, z } from 'zod';
import { ModelMessageObject } from "./types";
import type { ToolMessage, Message } from "./types";
import { Identifier } from "../id/id";
import { Storage } from "../storage";
import { Session } from "../session";

export namespace Messages {

  const StreamInput = z.object({
    sessionId: Identifier.schema("session"),
  });

  export async function* stream (input: z.output<typeof StreamInput>) {
    const list = await Array.fromAsync(await Storage.list(["message", input.sessionId]));
    for (let i = list.length - 1; i  >= 0; i--) {
      yield await get({
        sessionId: input.sessionId,
        messageId: list[i][2]
      })
    }
  }

  const GetInput = z.object({
    sessionId: Identifier.schema("session"),
    messageId: Identifier.schema("message")
  });

  export const get = async (input: z.output<typeof GetInput>) => {
    return await Storage.read<Message>(["message", input.sessionId, input.messageId]);
  }
  
  export function save(session: Session.SessionInfo, messages: Message[]) {
    fs.writeFileSync(
      session.rootPath + "/messages.json",
      JSON.stringify(messages, null, 2)
    );
  }
  
  export function saveSubagentMessages(
    orchestratorSession: Session.SessionInfo,
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

  /**
   * Save messages for a specific phase of subagent execution (init or attack)
   */
  export function saveSubagentPhaseMessages(
    subagentRootPath: string,
    phase: "init" | "attack",
    messages: any[]
  ) {
    const fileName = `${phase}-messages.json`;
    const filePath = `${subagentRootPath}/${fileName}`;

    fs.writeFileSync(
      filePath,
      JSON.stringify(messages, null, 2)
    );
  }
}

export function mapMessages(messages: Message[]): Message[] {
  const result: Message[] = [];

  // First pass: collect tool results to know which tool calls have completed
  const toolResults = new Map<string, any>();
  for (const message of messages) {
    if (message.role === "tool") {
      const content = message.content;
      if (Array.isArray(content)) {
        for (const part of content) {
          if (part.type === "tool-result") {
            toolResults.set(part.toolCallId, part.output);
          }
        }
      }
    }
  }

  // Second pass: process all messages
  for (const message of messages) {
    // Handle system messages
    if (message.role === "system") {
      result.push({
        id: Identifier.create("message", true),
        sessionId: message.sessionId,
        role: "system",
        content: message.content,
        createdAt: new Date(),
        ...(message.providerOptions && {
          providerOptions: message.providerOptions,
        }),
      });
      continue;
    }

    // Handle user messages
    if (message.role === "user") {
      const content =
        typeof message.content === "string"
          ? message.content
          : message.content
              .map((part) => (part.type === "text" ? part.text : ""))
              .join("");

      result.push({
        id: Identifier.create("message", true),
        sessionId: message.sessionId,
        role: "user",
        content,
        createdAt: new Date(),
        ...(message.providerOptions && {
          providerOptions: message.providerOptions,
        }),
      });
      continue;
    }

    // Skip tool messages from input - they're processed via tool results map
    if (message.role === "tool") {
      continue;
    }

    // Handle assistant messages (most complex case)
    if (message.role === "assistant") {
      const content = message.content;

      // Simple string content
      if (typeof content === "string") {
        result.push({
          id: Identifier.create("message", true),
          sessionId: message.sessionId,
          role: "assistant",
          content,
          createdAt: new Date(),
          ...(message.providerOptions && {
            providerOptions: message.providerOptions,
          }),
        });
        continue;
      }

      // Complex content array - need to extract text and create separate tool messages
      const textParts: string[] = [];
      const toolCalls: Array<{
        toolCallId: string;
        toolName: string;
        input: any;
      }> = [];

      for (const part of content) {
        if (part.type === "text") {
          textParts.push(part.text);
        } else if (part.type === "tool-call") {
          toolCalls.push({
            toolCallId: part.toolCallId,
            toolName: part.toolName,
            input: part.input,
          });
        }
      }

      // Add assistant message with text content only
      if (textParts.length > 0) {
        result.push({
          id: Identifier.create("message", true),
          sessionId: message.sessionId,
          role: "assistant",
          content: textParts.join(""),
          createdAt: new Date(),
          ...(message.providerOptions && {
            providerOptions: message.providerOptions,
          }),
        });
      }

      // Add tool messages for each tool call
      for (const toolCall of toolCalls) {
        const input = toolCall.input as Record<string, any>;
        const toolCallDescription =
          input?.toolCallDescription || `Executing ${toolCall.toolName}`;

        // Check if we have a result for this tool call
        const hasResult = toolResults.has(toolCall.toolCallId);

        result.push({
          id: Identifier.create("message", true),
          sessionId: message.sessionId,
          role: "tool",
          status: hasResult ? "completed" : "pending",
          toolCallId: toolCall.toolCallId,
          content: hasResult ? `✓ ${toolCallDescription}` : toolCallDescription,
          args: input || {},
          toolName: toolCall.toolName,
          createdAt: new Date(),
        });
      }
    }
  }

  return result;
}

export { type Message, type ToolMessage };
