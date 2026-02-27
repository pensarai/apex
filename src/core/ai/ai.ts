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
  | "openrouter"
  | "bedrock"
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
    errorMessage || errorName
      ? ""
      : String(error).toLowerCase();

  return (
    // Message-based detection
    errorMessage.includes("too many tokens") ||
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
const MAX_IDLE_RETRIES = 3;

// Between-step idle timeout: if no chunk arrives for this long after a tool
// result, the model API call is presumed hung and the stream is recreated.
const STREAM_IDLE_TIMEOUT_MS = 3 * 60 * 1000; // 3 minutes

class StreamIdleTimeoutError extends Error {
  constructor(idleMs: number) {
    super(
      `Stream idle for ${Math.round(idleMs / 1000)}s — no chunks received, presuming hung model call`,
    );
    this.name = "StreamIdleTimeoutError";
  }
}

/**
 * Iterate an async iterable with a per-chunk idle timeout.
 * If no new value arrives within `idleMs`, throws {@link StreamIdleTimeoutError}.
 */
async function* iterateWithIdleTimeout<T>(
  iterable: AsyncIterable<T>,
  idleMs: number,
  abortSignal?: AbortSignal,
): AsyncGenerator<T> {
  const iterator = iterable[Symbol.asyncIterator]();

  try {
    while (true) {
      let timer: ReturnType<typeof setTimeout> | undefined;

      const idlePromise = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new StreamIdleTimeoutError(idleMs)), idleMs);
      });

      // Also abort immediately if the agent's signal fires
      let abortCleanup: (() => void) | undefined;
      const abortPromise = abortSignal
        ? new Promise<never>((_, reject) => {
            const handler = () => reject(new Error("Stream aborted"));
            if (abortSignal.aborted) {
              handler();
              return;
            }
            abortSignal.addEventListener("abort", handler, { once: true });
            abortCleanup = () =>
              abortSignal.removeEventListener("abort", handler);
          })
        : null;

      try {
        const racers: Promise<IteratorResult<T>>[] = [
          iterator.next(),
          idlePromise,
        ];
        if (abortPromise) racers.push(abortPromise);

        const result = await Promise.race(racers);

        if (result.done) return;
        yield result.value;
      } finally {
        if (timer !== undefined) clearTimeout(timer);
        abortCleanup?.();
      }
    }
  } finally {
    // Ensure the underlying iterator is cleaned up
    await iterator.return?.();
  }
}

// Helper function to wrap a stream with error handling for async errors
function wrapStreamWithErrorHandler(
  originalStream: StreamTextResult<ToolSet, never>,
  messagesContainer: { current: ModelMessage[] },
  opts: StreamResponseOpts,
  model: LanguageModel,
  silent?: boolean,
  rateLimitRetryCount: number = 0,
  idleRetryCount: number = 0,
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
              for await (const chunk of iterateWithIdleTimeout(
                originalStream.fullStream,
                STREAM_IDLE_TIMEOUT_MS,
                opts.abortSignal,
              )) {
                // Check if this chunk contains an error
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

              // Handle idle timeout — recreate stream from accumulated messages
              const isIdle = error instanceof StreamIdleTimeoutError;
              if (isIdle && idleRetryCount < MAX_IDLE_RETRIES) {
                const nextIdleRetry = idleRetryCount + 1;
                if (!silent) {
                  console.warn(
                    `Stream idle timeout (retry ${nextIdleRetry}/${MAX_IDLE_RETRIES}), recreating stream with ${messagesContainer.current.length} messages`,
                  );
                }

                // Brief pause before retry
                await new Promise((resolve) => setTimeout(resolve, 2000));

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
                  0, // reset rate-limit counter on idle retry
                  nextIdleRetry,
                );

                for await (const chunk of wrappedRetriedStream.fullStream) {
                  yield chunk;
                }
                return;
              }

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
                  idleRetryCount,
                );

                for await (const chunk of wrappedRetriedStream.fullStream) {
                  yield chunk;
                }
                return;
              }

              // Handle context length errors with summarization
              const isCtxError = checkIfContextLengthError(error);

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
                if (!silent) {
                  console.warn(
                    `Context length error in wrapper, summarizing ${messagesContainer.current.length} messages: `,
                    errorMessage,
                  );
                }

                const summarizationStream = createSummarizationStream(
                  currentMessages,
                  opts,
                  model,
                );
                for await (const chunk of summarizationStream.fullStream) {
                  yield chunk;
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
      if (!silent) {
        console.warn(
          `Context length error, summarizing ${messagesContainer.current.length} messages: `,
          outerErrorMessage,
        );
      }
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
