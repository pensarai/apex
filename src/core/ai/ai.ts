import { createAnthropic } from "@ai-sdk/anthropic";
import type { AnthropicMessagesModelId } from "@ai-sdk/anthropic/internal";
import { createOpenAI } from "@ai-sdk/openai";
import type { OpenAIChatModelId } from "@ai-sdk/openai/internal";
import { createOpenRouter } from "@openrouter/ai-sdk-provider";
import { createAmazonBedrock } from "@ai-sdk/amazon-bedrock";
import {
  generateObject,
  streamText,
  type ModelMessage,
  type StopCondition,
  type StreamTextOnStepFinishCallback,
  type StreamTextResult,
  type TextStreamPart,
  type ToolCallRepairFunction,
  type ToolChoice,
  type ToolSet,
} from "ai";
import { getModelInfo } from "./models";
import { getProviderModel, summarizeConversation } from "./utils";

export type AIModel = AnthropicMessagesModelId | OpenAIChatModelId | string; // For OpenRouter and Bedrock models

export type AIModelProvider =
  | "anthropic"
  | "openai"
  | "openrouter"
  | "bedrock"
  | "local";

// Available models with names
export interface ModelInfo {
  id: AIModel;
  name: string;
  provider: AIModelProvider;
  contextLength?: number;
}

export interface StreamResponseOpts {
  prompt: string;
  system?: string;
  model: AIModel;
  messages?: Array<ModelMessage>;
  stopWhen?:
    | StopCondition<NoInfer<ToolSet>>
    | StopCondition<NoInfer<ToolSet>>[];
  toolChoice?: ToolChoice<ToolSet>;
  tools?: ToolSet;
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
  abortSignal?: AbortSignal;
  activeTools?: string[];
}

export function streamResponse(
  opts: StreamResponseOpts
): StreamTextResult<ToolSet, never> {
  const {
    prompt,
    system,
    model,
    messages,
    stopWhen,
    toolChoice,
    tools,
    onStepFinish,
    abortSignal,
    activeTools,
  } = opts;
  let storedMessages: ModelMessage[] = [];
  const providerModel = getProviderModel(model);

  try {
  } catch (error) {
    const resumed = summarizeConversation(storedMessages, opts, providerModel);
    return resumed;
  }

  // Create the appropriate provider instance

  const response = streamText({
    model: providerModel,
    system,
    ...(messages ? { messages } : { prompt }),
    stopWhen,
    toolChoice,
    tools,
    prepareStep: (opts) => {
      storedMessages = opts.messages;
      return undefined;
    },
    onStepFinish,
    abortSignal,
    activeTools,
    experimental_repairToolCall: async ({
      toolCall,
      inputSchema,
      tools,
      error,
    }) => {
      const { object: repairedArgs } = await generateObject({
        model: providerModel,
        schema: inputSchema.arguments,
        prompt: [
          `The model tried to call the tool "${toolCall.toolName}"` +
            ` with the following inputs:`,
          JSON.stringify(inputSchema.arguments),
          `The tool accepts the following schema:`,
          JSON.stringify(inputSchema.arguments),
          "Please fix the inputs.",
        ].join("\n"),
      });

      return { ...toolCall, input: JSON.stringify(repairedArgs) };
    },
  });

  return response;
}
