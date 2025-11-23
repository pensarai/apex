import type { Session } from "../agent/sessions";
import fs from "fs";
import { z } from 'zod';
import { ModelMessageObject } from "./types";
import type { ToolMessage } from "./types";

type Message = z.infer<typeof ModelMessageObject>;


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

export {
  type Message,
  type ToolMessage
};