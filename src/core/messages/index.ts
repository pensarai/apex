import type { ModelMessage } from "ai";
import type { Session } from "../agent/sessions";
import fs from "fs";
export interface ToolMessage {
  role: "tool";
  status: "pending" | "completed";
  toolCallId: string;
  content: string;
  args: Record<string, any>;
  toolName: string;
}

export type Message = ModelMessage | ToolMessage;

export function getMessages(session: Session): Message[] {
  const messages = fs.readFileSync(session.rootPath + "/messages.json", "utf8");
  return JSON.parse(messages);
}

export function saveMessages(session: Session, messages: Message[]) {
  fs.writeFileSync(
    session.rootPath + "/messages.json",
    JSON.stringify(messages, null, 2)
  );
}
