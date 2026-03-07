import type { AnthropicMessagesModelId } from "@ai-sdk/anthropic/internal";
import type { OpenAIChatModelId } from "@ai-sdk/openai/internal";
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
  type TextStreamPart,
  type ToolChoice,
  type ToolSet,
} from "ai";
import { z } from "zod";
import {
  checkIfContextLengthError,
  createSummarizationStream,
  getProviderModel,
  type AIAuthConfig,
} from "./utils";

export type AIModel = AnthropicMessagesModelId | OpenAIChatModelId | string; // For OpenRouter and Bedrock models

export type AIModelProvider =
  | "anthropic"
  | "openai"
  | "google"
  | "openrouter"
  | "bedrock"
  | "pensar"
  | "local";

function checkIfRateLimitError(error: unknown): boolean {
  const errObj =
    typeof error === "object" && error !== null
      ? (error as Record<string, unknown>)
      : {};

  // Check message — works for both Error instances and plain objects
  // (Bedrock streaming errors are plain { message: "..." } records)
  const errorMessage = (
    typeof errObj.message === "string" ? errObj.message : ""
  ).toLowerCase();
  const errorCode = String(
    typeof errObj.code === "string" ? errObj.code : "",
  ).toLowerCase();
  // AWS SDK errors surface the exception type via .name
  const errorName = (
    typeof errObj.name === "string" ? errObj.name : ""
  ).toLowerCase();
  // Bedrock HTTP-level errors include $metadata.httpStatusCode
  const httpStatus =
    typeof errObj.$metadata === "object" && errObj.$metadata !== null
      ? (errObj.$metadata as Record<string, unknown>).httpStatusCode
      : undefined;
  // Stringified fallback for opaque error objects (e.g. Bedrock stream records)
  const errorString =
    errorMessage || errorName ? "" : String(error).toLowerCase();

  return (
    // Message-based detection
    errorMessage.includes("rate limit") ||
    errorMessage.includes("request rate") ||
    errorMessage.includes("throttl") ||
    errorMessage.includes("overloaded") ||
    errorMessage.includes("too many requests") ||
    errorMessage.includes("please wait") ||
    errorMessage.includes("service unavailable") ||
    // AWS SDK exception names (ThrottlingException, TooManyRequestsException)
    errorName.includes("throttl") ||
    errorName.includes("toomanyrequests") ||
    errorName.includes("serviceunavailable") ||
    // Error codes
    errorCode === "rate_limit_exceeded" ||
    errorCode === "throttling" ||
    errorCode === "429" ||
    // HTTP status from AWS SDK $metadata
    httpStatus === 429 ||
    httpStatus === 529 ||
    httpStatus === 503 ||
    // Fallback: stringified error for opaque Bedrock stream records
    errorString.includes("throttl") ||
    errorString.includes("too many") ||
    errorString.includes("request rate")
  );
}

const MAX_RATE_LIMIT_RETRIES = 20;

// Helper function to wrap a stream with error handling for async errors
function wrapStreamWithErrorHandler(
  originalStream: StreamTextResult<ToolSet, never>,
  messagesContainer: { current: ModelMessage[] },
  opts: StreamResponseOpts,
  model: LanguageModel,
  silent?: boolean,
  rateLimitRetryCount: number = 0,
): StreamTextResult<ToolSet, never> {
  // Create a lazy getter for fullStream that wraps it with error handling
  let wrappedStream: AsyncIterable<TextStreamPart<ToolSet>> | null = null;

  const handler = {
    get(target: StreamTextResult<ToolSet, never>, prop: string | symbol) {
      // Intercept access to fullStream
      if (prop === "fullStream") {
        if (!wrappedStream) {
          wrappedStream = (async function* () {
            try {
              for await (const chunk of originalStream.fullStream) {
                if (chunk.type === "error" || "error" in chunk) {
                  const error =
                    "error" in chunk
                      ? (chunk as unknown as { error: unknown }).error
                      : chunk;
                  throw error;
                }

                yield chunk;
              }
            } catch (error) {
              const errorMessage =
                error instanceof Error ? error.message : String(error);

              // Check context length FIRST — "too many tokens" errors from
              // providers like Bedrock indicate input is too large, not a rate
              // limit. Summarize rather than blindly retrying the same payload.
              const isCtxError = checkIfContextLengthError(error);

              if (!isCtxError) {
                // Handle rate limit errors with exponential backoff retry
                if (
                  checkIfRateLimitError(error) &&
                  rateLimitRetryCount < MAX_RATE_LIMIT_RETRIES
                ) {
                  const nextRetryCount = rateLimitRetryCount + 1;
                  const delayMs = Math.min(1000 * nextRetryCount, 30000);

                  if (!silent) {
                    console.warn(
                      `Rate limit error (attempt ${nextRetryCount}/${MAX_RATE_LIMIT_RETRIES}), waiting ${delayMs}ms: ${errorMessage}`,
                    );
                  }

                  await new Promise((resolve) => setTimeout(resolve, delayMs));

                  const retriedStream = streamResponse({
                    ...opts,
                    messages:
                      messagesContainer.current.length > 0
                        ? messagesContainer.current
                        : undefined,
                  });

                  const wrappedRetriedStream = wrapStreamWithErrorHandler(
                    retriedStream,
                    messagesContainer,
                    opts,
                    model,
                    silent,
                    nextRetryCount,
                  );

                  for await (const chunk of wrappedRetriedStream.fullStream) {
                    yield chunk;
                  }
                  return;
                }
              }

              if (isCtxError) {
                let currentMessages: ModelMessage[] = messagesContainer.current;
                try {
                  const response = await originalStream.response;
                  if (response.messages && response.messages.length > 0) {
                    currentMessages = response.messages as ModelMessage[];
                  }
                } catch {
                  // Fall back to container messages if response is not available
                }
                console.warn(
                  `[RLM] Context length error, summarizing ${currentMessages.length} messages: ${errorMessage}`,
                );

                try {
                  const summarizationStream = createSummarizationStream(
                    currentMessages,
                    opts,
                    model,
                  );
                  for await (const chunk of summarizationStream.fullStream) {
                    yield chunk;
                  }
                } catch (summarizationError) {
                  // If summarization itself fails, log and re-throw the
                  // original error so the consumer can handle it gracefully.
                  console.error(
                    `[RLM] Summarization failed:`,
                    summarizationError instanceof Error
                      ? summarizationError.message
                      : String(summarizationError),
                  );
                  throw error;
                }
              } else {
                if (!silent) {
                  console.error(
                    "Non-recoverable stream error, re-throwing:",
                    errorMessage,
                  );
                }
                throw error;
              }
            }
          })();
        }
        return wrappedStream;
      }

      // For all other properties, return the original
      return (originalStream as unknown as Record<string | symbol, unknown>)[
        prop
      ];
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

/**
 * Truncate tool-result content in older messages to keep the conversation
 * within context limits. The most recent `keepRecent` tool-result messages
 * (role === "tool") are left intact; older ones have their output values
 * replaced with a short preview.
 *
 * The Vercel AI SDK stores tool results as:
 *   { type: "tool-result", toolCallId, toolName, output: { type: "json", value: {...} } }
 *
 * Mutates `messages` in place.
 */
function trimOldToolResults(
  messages: ModelMessage[],
  keepRecent: number,
): void {
  const MAX_RESULT_CHARS = 300;

  // Collect indices of all tool-result messages (role === "tool")
  const toolMsgIndices: number[] = [];
  for (let i = 0; i < messages.length; i++) {
    if (messages[i]!.role === "tool") {
      toolMsgIndices.push(i);
    }
  }

  if (toolMsgIndices.length <= keepRecent) return;

  const trimCount = toolMsgIndices.length - keepRecent;

  for (let t = 0; t < trimCount; t++) {
    const msg = messages[toolMsgIndices[t]!]!;
    if (!Array.isArray(msg.content)) continue;

    msg.content = msg.content.map((part: Record<string, unknown>) => {
      if (part.type !== "tool-result") return part;

      // Handle output: { type: "json", value: ... }
      const output = part.output as
        | { type: string; value: unknown }
        | undefined;
      if (output?.value != null) {
        const valueStr =
          typeof output.value === "string"
            ? output.value
            : JSON.stringify(output.value);
        if (valueStr.length > MAX_RESULT_CHARS) {
          return {
            ...part,
            output: {
              ...output,
              value: valueStr.slice(0, MAX_RESULT_CHARS) + "... [truncated]",
            },
          };
        }
      }

      // Handle direct result field (fallback)
      if (part.result != null) {
        const resultStr =
          typeof part.result === "string"
            ? part.result
            : JSON.stringify(part.result);
        if (resultStr.length > MAX_RESULT_CHARS) {
          return {
            ...part,
            result: resultStr.slice(0, MAX_RESULT_CHARS) + "... [truncated]",
          };
        }
      }

      return part;
    });
  }
}

export function streamResponse(
  opts: StreamResponseOpts,
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

        // Trim old tool results to prevent context overflow.
        // Keep the last N tool-result messages intact; older ones get
        // their content replaced with a short summary. This mirrors how
        // Claude Code compresses older context.
        const KEEP_RECENT_TOOL_RESULTS = 6;
        trimOldToolResults(opts.messages, KEEP_RECENT_TOOL_RESULTS);

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
        try {
          if (!silent) {
            console.log(`🔧 Repairing tool call: ${toolCall.toolName}`);
            console.log(`   Error: ${error.message || error}`);

            // Log specific details for common enum errors
            if (
              error.message &&
              (error.message.includes("severity") ||
                error.message.includes("riskLevel"))
            ) {
              console.log(
                `   Note: This appears to be an enum validation error. Tool call repair will normalize the value.`,
              );
            }
          }

          // Get the actual tool definition which contains the Zod schema
          const tool = tools[toolCall.toolName];
          if (!tool || !tool.inputSchema) {
            throw new Error(
              `Tool ${toolCall.toolName} not found or has no schema`,
            );
          }

          // Get JSONSchema7 for display purposes
          const jsonSchema = inputSchema({ toolName: toolCall.toolName });

          const { output: repairedArgs, usage: repairUsage } =
            await generateText({
              model: providerModel,
              output: Output.object({
                schema: tool.inputSchema, // Use the actual Zod schema from the tool
              }),
              prompt: [
                `The model tried to call the tool "${toolCall.toolName}"` +
                  ` with the following inputs:`,
                toolCall.input,
                `The tool accepts the following schema:`,
                JSON.stringify(jsonSchema),
                `Error encountered: ${error}`,
                "Please fix the inputs to match the schema.",
                "",
                "IMPORTANT: For enum fields like 'severity' or 'riskLevel', use ONLY the exact values from the enum (e.g., 'HIGH', 'CRITICAL', 'MEDIUM', 'LOW').",
                "Do not add prefixes, suffixes, or formatting characters like '>', '-', '!', etc.",
              ].join("\n"),
            });

          // Report tool repair token usage if onStepFinish callback is provided
          if (onStepFinish && repairUsage) {
            onStepFinish({
              text: "",
              reasoning: undefined,
              reasoningDetails: [],
              files: [],
              sources: [],
              toolCalls: [],
              toolResults: [],
              finishReason: "stop",
              usage: {
                inputTokens: repairUsage.inputTokens ?? 0,
                outputTokens: repairUsage.outputTokens ?? 0,
                totalTokens: repairUsage.totalTokens ?? 0,
              },
              warnings: [],
              request: {},
              response: {
                id: "tool-repair",
                timestamp: new Date(),
                modelId: "",
                messages: [],
              },
              providerMetadata: undefined,
              stepType: "initial",
              isContinued: false,
            } as unknown as Parameters<
              StreamTextOnStepFinishCallback<ToolSet>
            >[0]);
          }

          // Return the tool call with stringified repaired arguments
          if (repairedArgs === undefined || repairedArgs === null) {
            throw new Error(
              `Tool call repair for "${toolCall.toolName}" produced no valid output`,
            );
          }
          return { ...toolCall, input: JSON.stringify(repairedArgs) };
        } catch (repairError) {
          if (!silent) {
            console.error(
              "Error repairing tool call:",
              repairError instanceof Error
                ? repairError.message
                : String(repairError),
            );
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
      silent,
    );
  } catch (error) {
    // Check if the error is related to context length
    const isContextLengthError = checkIfContextLengthError(error);
    const outerErrorMessage =
      error instanceof Error ? error.message : String(error);

    if (isContextLengthError) {
      console.warn(
        `[RLM] Context length error (outer), summarizing ${messagesContainer.current.length} messages: ${outerErrorMessage}`,
      );
      // Return a wrapped stream that shows summarization and then continues
      return createSummarizationStream(
        messagesContainer.current,
        opts,
        providerModel,
      );
    }
    if (!silent) {
      console.error("Non-context length error, re-throwing", outerErrorMessage);
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
  opts: GenerateObjectOpts<T>,
) {
  const {
    model,
    schema,
    prompt,
    system,
    maxTokens,
    temperature,
    authConfig,
    onTokenUsage,
  } = opts;

  const providerModel = getProviderModel(model, authConfig);

  const { output, usage } = await generateText({
    model: providerModel,
    output: Output.object({
      schema,
    }),
    prompt,
    system,
    maxOutputTokens: maxTokens,
    temperature,
  });

  // Report token usage if callback provided
  if (onTokenUsage && usage) {
    onTokenUsage(usage.inputTokens ?? 0, usage.outputTokens ?? 0);
  }

  return output;
}
