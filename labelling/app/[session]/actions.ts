"use server";

import { readFileSync, writeFileSync } from "fs";

export interface Message {
  role: "user" | "assistant" | "tool";
  content: string;
  createdAt: string;
  status?: string;
  toolCallId?: string;
  args?: Record<string, any>;
  toolName?: string;
}

export async function readMessagesFile(
  filePath: string
): Promise<Message[] | null> {
  try {
    const content = readFileSync(filePath, "utf-8");
    return JSON.parse(content) as Message[];
  } catch (error) {
    console.error("Error reading messages file:", error);
    return null;
  }
}

export async function saveMessagesFile(
  filePath: string,
  messages: Message[]
): Promise<{ success: boolean; error?: string }> {
  try {
    writeFileSync(filePath, JSON.stringify(messages, null, 2), "utf-8");
    return { success: true };
  } catch (error) {
    console.error("Error saving messages file:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

