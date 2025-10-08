import { createAnthropic } from "@ai-sdk/anthropic";
import type { AnthropicMessagesModelId } from "@ai-sdk/anthropic/internal";
import {
  streamText,
  type ModelMessage,
  type StopCondition,
  type ToolChoice,
  type ToolSet,
} from "ai";

export type AIModel = AnthropicMessagesModelId;

export interface GetResponseProps {
  prompt: string;
  system?: string;
  model: AIModel;
  messages?: Array<ModelMessage>;
  stopWhen?:
    | StopCondition<NoInfer<ToolSet>>
    | StopCondition<NoInfer<ToolSet>>[];
  toolChoice?: ToolChoice<ToolSet>;
  tools?: ToolSet;
}

export function streamResponse(opts: GetResponseProps) {
  const { prompt, system, model, messages, stopWhen, toolChoice, tools } = opts;
  const anthropic = createAnthropic({
    apiKey: process.env.ANTHROPIC_API_KEY,
  });

  const response = streamText({
    model: anthropic(model),
    system,
    ...(messages ? { messages } : { prompt }),
    stopWhen,
    toolChoice,
    tools,
  });

  return response;
}
