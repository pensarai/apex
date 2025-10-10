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
  createdAt: Date;
}

export type Message = (ModelMessage & { createdAt: Date }) | ToolMessage;

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
