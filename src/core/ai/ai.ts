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
import { z } from "zod";
import { getModelInfo } from "./models";
import {
  checkIfContextLengthError,
  createSummarizationStream,
  getProviderModel,
  summarizeConversation,
  type AIAuthConfig,
} from "./utils";
import { traceAICall, isBraintrustEnabled, sanitizeToolInput, sanitizeToolOutput } from "../braintrust";
import { config } from "../config";
import type { Config } from "../config/config";

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
  messagesContainer: { current: ModelMessage[] },
  opts: StreamResponseOpts,
  model: LanguageModel,
  silent?: boolean
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
                // Try to get the actual messages that were sent to the API
                // from the stream's response property
                let currentMessages: ModelMessage[] = messagesContainer.current;
                try {
                  const response = await originalStream.response;
                  if (response.messages && response.messages.length > 0) {
                    currentMessages = response.messages as ModelMessage[];
                  }
                } catch (e) {
                  // Fall back to container messages if response is not available
                }
                if (!silent) {
                  console.warn(
                    `Context length error in wrapper, summarizing ${messagesContainer.current.length} messages: `,
                    error.message
                  );
                }

                const summarizationStream = createSummarizationStream(
                  currentMessages,
                  opts,
                  model
                );
                for await (const chunk of summarizationStream.fullStream) {
                  yield chunk;
                }
              } else {
                if (!silent) {
                  console.error(
                    "Non-context length error, re-throwing",
                    error.message
                  );
                }
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
  silent?: boolean;
  authConfig?: AIAuthConfig;
}

// Helper to get provider from model string
function getProviderFromModel(model: AIModel): AIModelProvider {
  if (typeof model === 'string') {
    if (model.startsWith('claude')) return 'anthropic';
    if (model.startsWith('gpt') || model.startsWith('o1')) return 'openai';
    if (model.includes('bedrock')) return 'bedrock';
    return 'openrouter';
  }
  return 'anthropic'; // Default
}

// Helper to wrap onStepFinish with Braintrust tracing
// Uses lazy config loading to work with synchronous streamResponse signature
function wrapOnStepFinishWithTracing(
  originalCallback: StreamTextOnStepFinishCallback<ToolSet> | undefined,
  model: AIModel,
  provider: AIModelProvider
): StreamTextOnStepFinishCallback<ToolSet> | undefined {
  if (!originalCallback) {
    return undefined;
  }

  // Lazy-load config on first callback invocation
  // This maintains the async context from the parent agent span
  let appConfigPromise: Promise<Config> | null = null;

  // Return wrapped callback that traces each step
  // Since this callback is invoked inside the agent's traced context,
  // spans created here will automatically nest under the parent agent span
  return async (step) => {
    // Lazy-load config on first invocation
    if (!appConfigPromise) {
      appConfigPromise = config.get();
    }

    const appConfig = await appConfigPromise;

    // If Braintrust is disabled, just call original
    if (!isBraintrustEnabled(appConfig)) {
      await originalCallback(step);
      return;
    }

    await traceAICall(
      appConfig,
      'streamText-step',
      {
        model,
        provider,
        has_tools: step.toolCalls && step.toolCalls.length > 0,
        tool_count: step.toolCalls ? step.toolCalls.length : 0,
      },
      async (updateMetadata) => {
        // Update with the actual agent output (thinking text, tool calls, results)
        updateMetadata({
          // The agent's reasoning/thinking text - THIS IS CRITICAL
          text_content: step.text || '',
          // Tool calls the agent decided to make
          tool_calls: step.toolCalls ? step.toolCalls.map(tc => ({
            tool_name: tc.toolName,
            tool_call_id: tc.toolCallId,
            args: sanitizeToolInput((tc as any).args),
          })) : [],
          // Tool results that came back
          tool_results: step.toolResults ? step.toolResults.map(tr => ({
            tool_name: tr.toolName,
            tool_call_id: tr.toolCallId,
            result: sanitizeToolOutput((tr as any).result),
          })) : [],
          // Token usage
          prompt_tokens: step.usage?.inputTokens ?? 0,
          completion_tokens: step.usage?.outputTokens ?? 0,
          total_tokens: (step.usage?.inputTokens ?? 0) + (step.usage?.outputTokens ?? 0),
        });

        // Call original callback
        await originalCallback(step);
      }
    );
  };
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
    silent,
    authConfig,
  } = opts;
  // Use a container object so the reference stays stable but the value can be updated
  const messagesContainer = { current: messages || [] };
  const providerModel = getProviderModel(model, authConfig);
  const provider = getProviderFromModel(model);

  // Wrap onStepFinish with Braintrust tracing
  // The wrapper lazily loads config on first invocation to maintain async context
  const wrappedOnStepFinish = wrapOnStepFinishWithTracing(
    onStepFinish,
    model,
    provider
  );

  try {
    // Create the appropriate provider instance
    const response = streamText({
      model: providerModel,
      system,
      ...(messages ? { messages } : { prompt }),
      stopWhen,
      toolChoice,
      tools,
      maxRetries: 3,
      prepareStep: (opts) => {
        // Update the container with the latest messages
        messagesContainer.current = opts.messages;
        return undefined;
      },
      onStepFinish: wrappedOnStepFinish,
      abortSignal,
      activeTools,
      experimental_repairToolCall: async ({
        toolCall,
        inputSchema,
        tools,
        error,
      }) => {
        try {
          if (!silent) {
            console.log(
              "Repairing tool call:",
              toolCall.toolName,
              "Error:",
              error
            );
          }

          // Get the actual tool definition which contains the Zod schema
          const tool = tools[toolCall.toolName];
          if (!tool || !tool.inputSchema) {
            throw new Error(
              `Tool ${toolCall.toolName} not found or has no schema`
            );
          }

          // Get JSONSchema7 for display purposes
          const jsonSchema = inputSchema({ toolName: toolCall.toolName });

          const { object: repairedArgs } = await generateObject({
            model: providerModel,
            schema: tool.inputSchema, // Use the actual Zod schema from the tool
            prompt: [
              `The model tried to call the tool "${toolCall.toolName}"` +
                ` with the following inputs:`,
              toolCall.input,
              `The tool accepts the following schema:`,
              JSON.stringify(jsonSchema),
              `Error encountered: ${error}`,
              "Please fix the inputs to match the schema.",
            ].join("\n"),
          });

          // Return the tool call with stringified repaired arguments
          return { ...toolCall, input: JSON.stringify(repairedArgs) };
        } catch (repairError: any) {
          if (!silent) {
            console.error("Error repairing tool call:", repairError.message);
          }
          throw repairError;
        }
      },
    });

    // Wrap the stream to catch async errors during consumption
    return wrapStreamWithErrorHandler(
      response,
      messagesContainer,
      opts,
      providerModel,
      silent
    );
  } catch (error: any) {
    // Check if the error is related to context length
    const isContextLengthError = checkIfContextLengthError(error);

    if (isContextLengthError) {
      if (!silent) {
        console.warn(
          `Context length error, summarizing ${messagesContainer.current.length} messages: `,
          error.message
        );
      }
      // Return a wrapped stream that shows summarization and then continues
      return createSummarizationStream(
        messagesContainer.current,
        opts,
        providerModel
      );
    }
    if (!silent) {
      console.error("Non-context length error, re-throwing", error.message);
    }

    // Re-throw if it's not a context length error
    throw error;
  }
}

export interface GenerateObjectOpts<T extends z.ZodType> {
  model: AIModel;
  schema: T;
  prompt: string;
  system?: string;
  maxTokens?: number;
  temperature?: number;
  authConfig?: AIAuthConfig;
}

export async function generateObjectResponse<T extends z.ZodType>(
  opts: GenerateObjectOpts<T>
) {
  const { model, schema, prompt, system, maxTokens, temperature, authConfig } =
    opts;

  const providerModel = getProviderModel(model, authConfig);
  const provider = getProviderFromModel(model);
  const appConfig = await config.get();

  // If Braintrust is disabled, just call directly
  if (!isBraintrustEnabled(appConfig)) {
    const { object } = await generateObject({
      model: providerModel,
      schema,
      prompt,
      system,
      maxTokens,
      temperature,
    });
    return object;
  }

  // Wrap with Braintrust tracing
  return await traceAICall(
    appConfig,
    'generateObject',
    {
      model,
      provider,
      has_tools: false,
      tool_count: 0,
    },
    async (updateMetadata) => {
      const result = await generateObject({
        model: providerModel,
        schema,
        prompt,
        system,
        maxTokens,
        temperature,
      });

      // Update metadata with token usage if available
      if (result.usage) {
        const usage = result.usage as any;
        updateMetadata({
          prompt_tokens: usage.promptTokens ?? usage.inputTokens ?? 0,
          completion_tokens: usage.completionTokens ?? usage.outputTokens ?? 0,
          total_tokens: usage.totalTokens ?? ((usage.inputTokens ?? 0) + (usage.outputTokens ?? 0)),
        });
      }

      return result.object;
    }
  );
}
