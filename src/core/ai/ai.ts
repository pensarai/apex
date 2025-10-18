import { createAnthropic } from "@ai-sdk/anthropic";
import type { AnthropicMessagesModelId } from "@ai-sdk/anthropic/internal";
import { createOpenAI } from "@ai-sdk/openai";
import type { OpenAIChatModelId } from "@ai-sdk/openai/internal";
import { createOpenRouter } from "@openrouter/ai-sdk-provider";
import { createAmazonBedrock } from "@ai-sdk/amazon-bedrock";
import {
  generateObject,
  streamText,
  type LanguageModel,
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
import {
  checkIfContextLengthError,
  createSummarizationStream,
  getProviderModel,
  summarizeConversation,
} from "./utils";

export type AIModel = AnthropicMessagesModelId | OpenAIChatModelId | string; // For OpenRouter and Bedrock models

export type AIModelProvider =
  | "anthropic"
  | "openai"
  | "openrouter"
  | "bedrock"
  | "local";

// Helper function to wrap a stream with error handling for async errors
function wrapStreamWithErrorHandler(
  originalStream: StreamTextResult<ToolSet, never>,
  messages: ModelMessage[],
  opts: StreamResponseOpts,
  model: LanguageModel
): StreamTextResult<ToolSet, never> {
  // Create a lazy getter for fullStream that wraps it with error handling
  let wrappedStream: any = null;

  const handler = {
    get(target: any, prop: string) {
      // Intercept access to fullStream
      if (prop === "fullStream") {
        if (!wrappedStream) {
          wrappedStream = (async function* () {
            try {
              for await (const chunk of originalStream.fullStream) {
                // Check if this chunk contains an error
                if (chunk.type === "error" || (chunk as any).error) {
                  const error = (chunk as any).error || chunk;
                  throw error;
                }

                yield chunk;
              }
            } catch (error: any) {
              // Check if it's a context length error
              const isContextLengthError = checkIfContextLengthError(error);

              if (isContextLengthError) {
                console.log("Context length error, summarizing conversation");
                // Create a summarization stream and yield its events
                const summarizationStream = createSummarizationStream(
                  messages,
                  opts,
                  model
                );
                for await (const chunk of summarizationStream.fullStream) {
                  yield chunk;
                }
              } else {
                console.log("Non-context length error, re-throwing");
                // Re-throw if it's not a context length error
                throw error;
              }
            }
          })();
        }
        return wrappedStream;
      }

      // For all other properties, return the original
      return (originalStream as any)[prop];
    },
  };

  return new Proxy(originalStream, handler);
}

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

    // Wrap the stream to catch async errors during consumption
    return wrapStreamWithErrorHandler(
      response,
      storedMessages,
      opts,
      providerModel
    );
  } catch (error: any) {
    // Check if the error is related to context length
    const isContextLengthError = checkIfContextLengthError(error);

    if (isContextLengthError) {
      console.log("Context length error, creating summarization stream");
      // Return a wrapped stream that shows summarization and then continues
      return createSummarizationStream(storedMessages, opts, providerModel);
    }

    console.log("Non-context length error, re-throwing");
    // Re-throw if it's not a context length error
    throw error;
  }
}
