import type { AnthropicMessagesModelId } from '@ai-sdk/anthropic/internal';
import type { OpenAIChatModelId } from '@ai-sdk/openai/internal';
import {
  generateText,
  Output,
  streamText,
  type LanguageModel,
  type ModelMessage,
  type StopCondition,
  type StreamTextOnFinishCallback,
  type StreamTextOnStepFinishCallback,
  type StreamTextResult,
  type ToolChoice,
  type ToolSet,
} from 'ai';
import { z } from 'zod';
import {
  checkIfContextLengthError,
  createSummarizationStream,
  findSimilarTools,
  getProviderModel,
  type AIAuthConfig,
} from './utils';

export type AIModel = AnthropicMessagesModelId | OpenAIChatModelId | string; // For OpenRouter and Bedrock models

export type AIModelProvider =
  | 'anthropic'
  | 'openai'
  | 'openrouter'
  | 'bedrock'
  | 'local'
  | 'baseten';

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
      if (prop === 'fullStream') {
        if (!wrappedStream) {
          wrappedStream = (async function* () {
            try {
              for await (const chunk of originalStream.fullStream) {
                // Check if this chunk contains an error
                if (chunk.type === 'error' || (chunk as any).error) {
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
                    'Non-context length error, re-throwing',
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
  onFinish?: StreamTextOnFinishCallback<ToolSet>;
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
    onFinish,
  } = opts;
  // Use a container object so the reference stays stable but the value can be updated
  const messagesContainer = { current: messages || [] };
  const providerModel = getProviderModel(model, authConfig);

  let rateLimitRetryCount = 0;
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
      onError: async ({ error }: { error: any }) => {
        if (
          error.message.toLowerCase().includes('too many tokens') ||
          error.message.toLowerCase().includes('overloaded')
        ) {
          rateLimitRetryCount++;
          await new Promise((resolve) =>
            setTimeout(resolve, 1000 * rateLimitRetryCount)
          );
          if (rateLimitRetryCount < 20) {
            return;
          }
        }
        throw error;
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
        try {
          if (!silent) {
            console.log(
              `🔧 Repairing tool call: ${toolCall.toolName}`
            );
            console.log(`   Error: ${error.message || error}`);

            // Log specific details for common enum errors
            if (error.message && (error.message.includes('severity') || error.message.includes('riskLevel'))) {
              console.log(`   Note: This appears to be an enum validation error. Tool call repair will normalize the value.`);
            }
          }

          // Get the actual tool definition which contains the Zod schema
          const tool = tools[toolCall.toolName];
          if (!tool || !tool.inputSchema) {
            const fuzzyMatchedTool = findSimilarTools(toolCall.toolName, Object.keys(tools));
            throw new Error(
              `Tool ${toolCall.toolName} not found or has no schema${fuzzyMatchedTool ? ` -> did you mean ${fuzzyMatchedTool}` : ""}`
            );
          }

          const jsonSchema = inputSchema({ toolName: toolCall.toolName });

          const { output: repairedArgs, usage: repairUsage } = await generateText({
            model: providerModel,
            output: Output.object({ schema: tool.inputSchema }), // Use the actual Zod schema from the tool
            prompt: [
              `The model tried to call the tool "${toolCall.toolName}"` +
                ` with the following inputs:`,
              toolCall.input,
              `The tool accepts the following schema:`,
              JSON.stringify(jsonSchema),
              `Error encountered: ${error}`,
              'Please fix the inputs to match the schema.',
               "",
              "IMPORTANT: For enum fields like 'severity' or 'riskLevel', use ONLY the exact values from the enum (e.g., 'HIGH', 'CRITICAL', 'MEDIUM', 'LOW').",
              "Do not add prefixes, suffixes, or formatting characters like '>', '-', '!', etc.",
            ].join('\n'),
          });

          // Report tool repair token usage if onStepFinish callback is provided
          if (onStepFinish && repairUsage) {
            onStepFinish({
              text: '',
              reasoning: undefined,
              reasoningDetails: [],
              files: [],
              sources: [],
              toolCalls: [],
              toolResults: [],
              finishReason: 'stop',
              usage: {
                inputTokens: repairUsage.inputTokens ?? 0,
                outputTokens: repairUsage.outputTokens ?? 0,
                totalTokens: repairUsage.totalTokens ?? 0,
              },
              warnings: [],
              request: {},
              response: {
                id: 'tool-repair',
                timestamp: new Date(),
                modelId: '',
              },
              providerMetadata: undefined,
              stepType: 'initial',
              isContinued: false,
            } as any);
          }

          // Return the tool call with stringified repaired arguments
          return { ...toolCall, input: JSON.stringify(repairedArgs) };
        } catch (repairError: any) {
          if (!silent) {
            console.error('Error repairing tool call:', repairError.message);
          }
          throw repairError;
        }
      },
      onFinish,
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
      console.error('Non-context length error, re-throwing', error.message);
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
  onTokenUsage?: (inputTokens: number, outputTokens: number) => void;
}

export async function generateObjectResponse<T extends z.ZodType>(
  opts: GenerateObjectOpts<T>
): Promise<z.infer<T>> {
  const { model, schema, prompt, system, maxTokens, temperature, authConfig, onTokenUsage } =
    opts;

  const providerModel = getProviderModel(model, authConfig);

  const { output, usage } = await generateText({
    model: providerModel,
    output: Output.object({ schema }),
    prompt,
    system,
    maxOutputTokens: maxTokens,
    temperature,
  });

  // Report token usage if callback provided
  if (onTokenUsage && usage) {
    onTokenUsage(usage.inputTokens ?? 0, usage.outputTokens ?? 0);
  }

  return output as z.infer<T>;
}
