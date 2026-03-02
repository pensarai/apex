import { z } from "zod";
import type { ToolMessage, Message } from "./types";
import * as Identifier from "../id/id";
import * as Storage from "../storage";

const StreamInput = z.object({
  sessionId: Identifier.schema("session"),
});

export async function* stream(input: z.output<typeof StreamInput>) {
  const list = await Array.fromAsync(
    await Storage.list(["message", input.sessionId]),
  );
  for (let i = list.length - 1; i >= 0; i--) {
    yield await get({
      sessionId: input.sessionId,
      messageId: list[i][2],
    });
  }
}

const GetInput = z.object({
  sessionId: Identifier.schema("session"),
  messageId: Identifier.schema("message"),
});

export const get = async (input: z.output<typeof GetInput>) => {
  return await Storage.read<Message>([
    "message",
    input.sessionId,
    input.messageId,
  ]);
};

export { type Message, type ToolMessage };
