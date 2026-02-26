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
  isAnthropicProvider,
  type AIAuthConfig,
} from "./utils";
import { withCachedSystemPrompt, withCachedLastMessage } from "./caching";

export type AIModel = AnthropicMessagesModelId | OpenAIChatModelId | string; // For OpenRouter and Bedrock models

/** Callback for reporting token usage from AI operations */
type UsageCallback = (
  model: string,
  inputTokens: number,
  outputTokens: number,
) => void;
let _usageCallback: UsageCallback | null = null;

/** Register a callback to receive token usage reports from all AI operations */
export function onUsage(cb: UsageCallback | null): void {
  _usageCallback = cb;
}

export type AIModelProvider =
  | "anthropic"
  | "openai"
  | "google"
  | "openrouter"
  | "bedrock"
  | "pensar"
  | "inception"
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

              // Check context length FIRST — these should never be retried
              // as-is; the prompt must be reduced via summarization.
              const isCtxError = checkIfContextLengthError(error);

              // Handle rate limit errors with exponential backoff retry
              if (
                !isCtxError &&
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

/** Cache token metrics extracted from Anthropic providerMetadata */
export interface CacheMetrics {
  cacheReadInputTokens: number;
  cacheCreationInputTokens: number;
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
  /**
   * Called when the context window overflows and the conversation is
   * summarized. Callers should use this to discard stale message history
   * so that subsequent persistence writes only include the summary +
   * new messages (not the full pre-summarization history).
   */
  onSummarized?: (summary: string) => void;
  /** Called when Anthropic cache metrics are present in a step's providerMetadata */
  onCacheMetrics?: (metrics: CacheMetrics) => void;
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
    onStepFinish: userOnStepFinish,
    abortSignal,
    activeTools,
    silent,
    authConfig,
    onFinish,
    onCacheMetrics,
  } = opts;

  // Wrap onStepFinish to fire usage callback for every step.
  // Must be async so that callers returning a Promise (e.g. MessageManager
  // persisting messages / queuing issues) are fully awaited before the
  // AI SDK starts the next step.
  const onStepFinish: typeof userOnStepFinish = async (step) => {
    await userOnStepFinish?.(step);
    if (_usageCallback) {
      const inp = step.usage?.inputTokens ?? 0;
      const out = step.usage?.outputTokens ?? 0;
      if (inp > 0 || out > 0) _usageCallback(model, inp, out);
    }
  };
  // Use a container object so the reference stays stable but the value can be updated
  const messagesContainer = { current: messages || [] };
  const providerModel = getProviderModel(model, authConfig);
  const useAnthropicCaching = isAnthropicProvider(model);

  // For Anthropic models, move the system prompt into messages with cache_control.
  // This caches tools + system prompt across multi-turn conversations (~90% cost reduction on cache hits).
  let effectiveSystem: string | undefined = system;
  let effectiveMessages: ModelMessage[] | undefined = messages;

  if (useAnthropicCaching && system) {
    const baseMessages: ModelMessage[] =
      messages ?? [{ role: "user" as const, content: prompt }];
    effectiveMessages = withCachedSystemPrompt(system, baseMessages);
    effectiveSystem = undefined;
  }

  try {
    // Create the appropriate provider instance
    const response = streamText({
      model: providerModel,
      system: effectiveSystem,
      ...(effectiveMessages ? { messages: effectiveMessages } : { prompt }),
      stopWhen,
      toolChoice,
      tools,
      maxRetries: 3,
      prepareStep: (opts) => {
        // Update the container with the latest messages
        messagesContainer.current = opts.messages;
        // For Anthropic, add cache_control to the last message for incremental caching
        if (useAnthropicCaching) {
          return { messages: withCachedLastMessage(opts.messages) };
        }
        return undefined;
      },
      onError: async ({ error }: { error: unknown }) => {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        if (
          errorMessage.toLowerCase().includes("too many tokens") ||
          errorMessage.toLowerCase().includes("overloaded")
        ) {
          rateLimitRetryCount++;
          await new Promise((resolve) =>
            setTimeout(resolve, 1000 * rateLimitRetryCount),
          );
          if (rateLimitRetryCount < 20) {
            return;
          }
        }
        throw error;
      },
      onStepFinish: onCacheMetrics
        ? (stepResult) => {
            // Extract Anthropic cache metrics from providerMetadata
            const meta = stepResult.providerMetadata?.anthropic as
              | Record<string, unknown>
              | undefined;
            const cacheRead =
              (meta?.cacheReadInputTokens as number) ?? 0;
            const cacheCreation =
              (meta?.cacheCreationInputTokens as number) ?? 0;
            if (cacheRead > 0 || cacheCreation > 0) {
              onCacheMetrics({ cacheReadInputTokens: cacheRead, cacheCreationInputTokens: cacheCreation });
            }
            onStepFinish?.(stepResult);
          }
        : onStepFinish,
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
              abortSignal,
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
  abortSignal?: AbortSignal;
  onTokenUsage?: (inputTokens: number, outputTokens: number) => void;
}

const MAX_OBJECT_RATE_LIMIT_RETRIES = 8;

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
    abortSignal,
    onTokenUsage,
  } = opts;

  const providerModel = getProviderModel(model, authConfig);

  let lastError: unknown;

  for (let attempt = 0; attempt <= MAX_OBJECT_RATE_LIMIT_RETRIES; attempt++) {
    try {
      const { output, usage } = await generateText({
        model: providerModel,
        output: Output.object({
          schema,
        }),
        prompt,
        system,
        maxOutputTokens: maxTokens,
        temperature,
        maxRetries: 0,
        abortSignal,
      });

      if (onTokenUsage && usage) {
        onTokenUsage(usage.inputTokens ?? 0, usage.outputTokens ?? 0);
      }

      if (_usageCallback && usage) {
        const inp = usage.inputTokens ?? 0;
        const out = usage.outputTokens ?? 0;
        if (inp > 0 || out > 0) _usageCallback(model, inp, out);
      }

      return output;
    } catch (error) {
      lastError = error;

      if (checkIfContextLengthError(error)) {
        const msg = error instanceof Error ? error.message : String(error);
        throw new ContextLengthError(
          `Prompt exceeds model context window: ${msg}`,
        );
      }

      if (
        checkIfRateLimitError(error) &&
        attempt < MAX_OBJECT_RATE_LIMIT_RETRIES
      ) {
        const delayMs = Math.min(1000 * 2 ** attempt, 60_000);
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        continue;
      }

      throw error;
    }
  }

  throw lastError;
}

export class ContextLengthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ContextLengthError";
  }
}
