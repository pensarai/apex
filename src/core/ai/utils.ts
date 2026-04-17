import { createOpenAI } from "@ai-sdk/openai";
import { streamResponse, type AIModel, type StreamResponseOpts } from "./ai";
import { extractTaskSummaryFromMessages } from "./contextManagement";
import { createOpenRouter } from "@openrouter/ai-sdk-provider";
import { createAmazonBedrock } from "@ai-sdk/amazon-bedrock";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { createAnthropic } from "@ai-sdk/anthropic";
import { createGoogleGenerativeAI } from "@ai-sdk/google";
import { getModelInfo } from "./models";
import { createPensarModel } from "./providers/pensar";
import { getPensarGatewayUrl } from "../api/constants";
import { ensureValidToken } from "../auth";
import { config } from "../config";
import {
  generateText,
  type LanguageModel,
  type ModelMessage,
  type StreamTextResult,
  type TextStreamPart,
  type ToolSet,
} from "ai";

/**
 * Check if a model uses an Anthropic-compatible provider that supports prompt caching.
 * Direct Anthropic, AWS Bedrock (Claude), and Pensar gateway (routes to Bedrock) all support cache_control.
 */
export function isAnthropicProvider(model: AIModel): boolean {
  const { provider } = getModelInfo(model);
  return (
    provider === "anthropic" || provider === "bedrock" || provider === "pensar"
  );
}

/**
 * Bun's fetch has a 300-second default timeout that can't be disabled via
 * AbortSignal. Providers streaming long model responses need a wider ceiling;
 * this helper composes a 1-hour timeout with any caller-provided signal.
 */
const STREAMING_FETCH_TIMEOUT_MS = 60 * 60 * 1000;

export function buildStreamingFetchSignal(
  callerSignal?: AbortSignal | null,
): AbortSignal {
  const timeout = AbortSignal.timeout(STREAMING_FETCH_TIMEOUT_MS);
  return callerSignal ? AbortSignal.any([callerSignal, timeout]) : timeout;
}

export type AIAuthConfig = {
  openAiAPIKey?: string;
  anthropicAPIKey?: string;
  googleAPIKey?: string;
  openRouterAPIKey?: string;
  inceptionAPIKey?: string;
  pensarAPIKey?: string;
  // WorkOS CLI auth
  accessToken?: string;
  refreshToken?: string;
  workspaceId?: string;
  // Gateway request signing
  gatewaySigningKey?: string;
  // Gateway URL for inference (bypasses CloudFront timeout)
  gatewayUrl?: string;
  bedrock?: {
    apiKey?: string;
    accessKeyId?: string;
    secretAccessKey?: string;
    sessionToken?: string;
    region?: string;
    credentialProvider?: unknown;
  };
  local?: {
    baseURL: string;
  };
};

/**
 * Build an AIAuthConfig from persisted config, converting null → undefined
 * and including Pensar/WorkOS fields alongside the standard provider keys.
 */
export function buildAuthConfig(cfg: {
  anthropicAPIKey?: string | null;
  openAiAPIKey?: string | null;
  googleAPIKey?: string | null;
  openRouterAPIKey?: string | null;
  inceptionAPIKey?: string | null;
  pensarAPIKey?: string | null;
  accessToken?: string | null;
  refreshToken?: string | null;
  workspaceId?: string | null;
  gatewaySigningKey?: string | null;
  gatewayUrl?: string | null;
  bedrockAPIKey?: string | null;
  localModelUrl?: string | null;
}): AIAuthConfig {
  return {
    anthropicAPIKey: cfg.anthropicAPIKey ?? undefined,
    openAiAPIKey: cfg.openAiAPIKey ?? undefined,
    googleAPIKey: cfg.googleAPIKey ?? undefined,
    openRouterAPIKey: cfg.openRouterAPIKey ?? undefined,
    inceptionAPIKey: cfg.inceptionAPIKey ?? undefined,
    pensarAPIKey: cfg.pensarAPIKey ?? undefined,
    accessToken: cfg.accessToken ?? undefined,
    refreshToken: cfg.refreshToken ?? undefined,
    workspaceId: cfg.workspaceId ?? undefined,
    gatewaySigningKey: cfg.gatewaySigningKey ?? undefined,
    gatewayUrl: cfg.gatewayUrl ?? undefined,
    bedrock: cfg.bedrockAPIKey ? { apiKey: cfg.bedrockAPIKey } : undefined,
    local: cfg.localModelUrl ? { baseURL: cfg.localModelUrl } : undefined,
  };
}

export function getProviderModel(
  model: AIModel,
  authConfig?: AIAuthConfig,
): LanguageModel {
  const { provider } = getModelInfo(model);

  const openAiAPIKey = authConfig?.openAiAPIKey || process.env.OPENAI_API_KEY;
  const anthropicAPIKey =
    authConfig?.anthropicAPIKey || process.env.ANTHROPIC_API_KEY;
  const googleAPIKey =
    authConfig?.googleAPIKey || process.env.GOOGLE_GENERATIVE_AI_API_KEY;
  const openRouterAPIKey =
    authConfig?.openRouterAPIKey || process.env.OPENROUTER_API_KEY;
  const bedrockApiKey =
    authConfig?.bedrock?.apiKey || process.env.BEDROCK_API_KEY;
  const bedrockAccessKeyId =
    authConfig?.bedrock?.accessKeyId || process.env.AWS_ACCESS_KEY_ID;
  const bedrockSecretAccessKey =
    authConfig?.bedrock?.secretAccessKey || process.env.AWS_SECRET_ACCESS_KEY;
  const bedrockSessionToken =
    authConfig?.bedrock?.sessionToken || process.env.AWS_SESSION_TOKEN;
  const bedrockRegion = authConfig?.bedrock?.region || process.env.AWS_REGION;
  const inceptionApiKey =
    authConfig?.inceptionAPIKey || process.env.INCEPTION_API_KEY;
  const localBaseURL =
    authConfig?.local?.baseURL ||
    process.env.LOCAL_MODEL_URL ||
    "http://127.0.0.1:1234/v1";

  let providerModel;

  switch (provider) {
    case "openai": {
      const openai = createOpenAI({
        apiKey: openAiAPIKey,
      });
      providerModel = openai(model);
      break;
    }

    case "openrouter": {
      const openrouter = createOpenRouter({
        apiKey: openRouterAPIKey,
      });
      providerModel = openrouter(model);
      break;
    }

    case "inception": {
      const inception = createOpenAICompatible({
        name: "inception",
        apiKey: inceptionApiKey,
        baseURL: "https://api.inceptionlabs.ai/v1",
      });
      providerModel = inception("mercury-2");
      break;
    }

    case "bedrock": {
      const bedrockFetch = (input: RequestInfo | URL, init?: RequestInit) =>
        globalThis.fetch(input, {
          ...init,
          signal: buildStreamingFetchSignal(init?.signal),
        });
      const bedrock = createAmazonBedrock({
        apiKey: bedrockApiKey,
        region: bedrockRegion,
        accessKeyId: bedrockAccessKeyId,
        secretAccessKey: bedrockSecretAccessKey,
        sessionToken: bedrockSessionToken,
        credentialProvider: authConfig?.bedrock
          ?.credentialProvider as NonNullable<
          Parameters<typeof createAmazonBedrock>[0]
        >["credentialProvider"],
        fetch: bedrockFetch as typeof globalThis.fetch,
      });
      providerModel = bedrock(model);
      break;
    }

    case "anthropic":
      providerModel = createAnthropic({
        apiKey: anthropicAPIKey,
      }).chat(model);
      break;

    case "google": {
      const google = createGoogleGenerativeAI({
        apiKey: googleAPIKey,
      });
      providerModel = google(model);
      break;
    }

    case "pensar": {
      const pensarApiKey =
        authConfig?.pensarAPIKey || process.env.PENSAR_API_KEY;
      const hasWorkOSAuth = !!authConfig?.accessToken;

      if (!pensarApiKey && !hasWorkOSAuth) {
        throw new Error(
          "Pensar not configured. Run /login to connect to Pensar Console.",
        );
      }

      const gatewayUrl = authConfig?.gatewayUrl || getPensarGatewayUrl();
      const bedrockModelId = model.startsWith("pensar:")
        ? model.slice(7)
        : model;
      if (
        process.env.PENSAR_DEBUG === "1" ||
        process.env.PENSAR_DEBUG === "true"
      ) {
        console.log(
          `[pensar] getProviderModel: ${model} → bedrock:${bedrockModelId} via ${gatewayUrl}`,
        );
      }

      // Build config with token refresh support for WorkOS auth
      const modelConfig: Parameters<typeof createPensarModel>[1] = {
        apiKey: pensarApiKey || authConfig?.accessToken || "",
        baseUrl: gatewayUrl,
        workspaceId: authConfig?.workspaceId,
        signingKey: authConfig?.gatewaySigningKey,
      };

      // If WorkOS tokens are available, use token refresh callback.
      // Read fresh config each time so rotated tokens are picked up
      // (WorkOS refresh tokens are single-use).
      if (hasWorkOSAuth) {
        modelConfig.getToken = async () => {
          const freshConfig = await config.get();
          return ensureValidToken({
            accessToken: freshConfig.accessToken,
            refreshToken: freshConfig.refreshToken,
            pensarAPIKey: freshConfig.pensarAPIKey,
          });
        };
      }

      providerModel = createPensarModel(bedrockModelId, modelConfig);
      break;
    }

    case "local":
      providerModel = createOpenAI({
        baseURL: localBaseURL,
        apiKey: "",
      }).chat(model);
      break;

    default: {
      const anthropic = createAnthropic({
        apiKey: anthropicAPIKey,
      });
      providerModel = anthropic(model);
      break;
    }
  }

  return providerModel;
}

export async function summarizeConversation(
  messages: ModelMessage[],
  opts: StreamResponseOpts,
  model: LanguageModel,
): Promise<StreamTextResult<ToolSet, never>> {
  // Filter and clean messages to remove tool calls/results
  // We only want conversational content for summarization
  const cleanMessages = messages
    .map((msg) => {
      // If content is an array, filter out tool-use and tool-result blocks
      if (Array.isArray(msg.content)) {
        const textContent = msg.content
          .filter(
            (part: { type: string; text?: string }) => part.type === "text",
          )
          .map((part: { type: string; text?: string }) => part.text)
          .join("\n");

        // Skip messages that have no text content
        if (!textContent.trim()) return null;

        return {
          role: msg.role,
          content: textContent,
        };
      }

      // Keep string content as-is
      return msg;
    })
    .filter(Boolean) as ModelMessage[];

  let slicedMessages: ModelMessage[] = [];
  if (
    cleanMessages.length === 1 &&
    typeof cleanMessages[0]!.content === "string"
  ) {
    // For a single message with very long content, take just the last portion
    const content = cleanMessages[0]!.content;
    const lines = content.split("\n");
    const truncatedContent = lines.slice(-50).join("\n"); // Last 50 lines

    slicedMessages = [
      {
        role: "user",
        content: truncatedContent,
      },
    ];
  } else {
    // Take the last 20 messages for context
    slicedMessages = cleanMessages.slice(-20);
  }

  const summarizedMessages: ModelMessage[] = [
    ...slicedMessages,
    {
      role: "user",
      content: `Summarize this conversation to pass to another agent. This was the system prompt: ${opts.system} `,
    },
  ];

  const { text: summary, usage: summaryUsage } = await generateText({
    model,
    system: `You are a helpful assistant that summarizes conversations to pass to another agent. Review the conversation and system prompt at the end provided by the user.`,
    messages: summarizedMessages,
    abortSignal: opts.abortSignal,
  });

  // Report summarization token usage if onStepFinish callback is provided
  // This ensures summarization tokens are tracked even though it's not a "step"
  if (opts.onStepFinish && summaryUsage) {
    // Create a minimal step finish event for the summarization
    opts.onStepFinish({
      text: "",
      reasoning: undefined,
      reasoningDetails: [],
      files: [],
      sources: [],
      toolCalls: [],
      toolResults: [],
      finishReason: "stop",
      usage: {
        inputTokens: summaryUsage.inputTokens ?? 0,
        outputTokens: summaryUsage.outputTokens ?? 0,
        totalTokens: summaryUsage.totalTokens ?? 0,
      },
      warnings: [],
      request: {},
      response: {
        id: "summarization",
        timestamp: new Date(),
        modelId: "",
      },
      providerMetadata: undefined,
      stepType: "initial",
      isContinued: false,
    } as unknown as Parameters<NonNullable<typeof opts.onStepFinish>>[0]);
  }

  // Preserve task state through summarization so the agent doesn't lose
  // track of its task progress after context compaction.
  const taskSummary = extractTaskSummaryFromMessages(messages);
  const summaryWithTasks = taskSummary
    ? `${summary}\n\nCurrent task state: ${taskSummary}`
    : summary;

  // For very long prompts, replace with just the summary instead of appending
  const originalLength =
    typeof opts.prompt === "string" ? opts.prompt.length : 0;
  const enhancedPrompt =
    originalLength > 100000
      ? `Context: The previous conversation contained very long content that was summarized.\n\nSummary: ${summaryWithTasks}\n\nOriginal task: Please respond based on this summary.`
      : `${opts.prompt}\n\nThe previous agent has summarized the conversation to pass to you to continue the task. Here is the summary: ${summaryWithTasks}`;

  // Notify callers that context was reset so they can discard stale history.
  opts.onSummarized?.(summary);

  // streamResponse always wraps with error handling, so if this call
  // also hits context length limits, it will recursively summarize again
  const resumed = streamResponse({
    ...opts,
    prompt: enhancedPrompt,
    messages: undefined,
  });
  return resumed;
}

// Helper function to check if an error is related to context length
export function checkIfContextLengthError(error: unknown): boolean {
  const errObj =
    typeof error === "object" && error !== null
      ? (error as Record<string, unknown>)
      : {};
  const errorMessage = (
    typeof errObj.message === "string" ? errObj.message : ""
  ).toLowerCase();
  const errorCode = String(
    typeof errObj.code === "string" ? errObj.code : "",
  ).toLowerCase();

  return (
    errorMessage.includes("context length") ||
    errorMessage.includes("context_length") ||
    errorMessage.includes("too long") ||
    errorMessage.includes("token limit") ||
    errorMessage.includes("maximum context") ||
    errorMessage.includes("context_length_exceeded") ||
    errorMessage.includes("tokens_exceeded") ||
    errorMessage.includes("maximum token") ||
    errorCode === "context_length_exceeded" ||
    errorCode === "tokens_exceeded"
  );
}

// Helper function to create a stream that shows summarization progress
export function createSummarizationStream(
  messages: ModelMessage[],
  opts: StreamResponseOpts,
  model: LanguageModel,
): StreamTextResult<ToolSet, never> {
  // Generate a unique tool call ID
  const toolCallId = `summarize-${Date.now()}`;

  // We need to handle this asynchronously but return synchronously
  // Create a promise that will hold the resumed stream
  // Start the summarization process
  const resumedStreamPromise: Promise<StreamTextResult<ToolSet, never>> =
    summarizeConversation(messages, opts, model);

  // Create a custom async generator that wraps the resumed stream
  const wrappedFullStream = (async function* () {
    // First, emit a synthetic tool-call event
    const toolCallEvent = {
      type: "tool-call" as const,
      toolCallId,
      toolName: "summarize_conversation",
      input: JSON.stringify({
        reason: "Context length exceeded, summarizing conversation to continue",
        messageCount: messages.length,
      }),
    } as unknown as TextStreamPart<ToolSet>;
    yield toolCallEvent;

    // Wait for the summarization to complete
    const resumedStream = await resumedStreamPromise;

    // Emit a synthetic tool-result event
    const toolResultEvent = {
      type: "tool-result" as const,
      toolCallId,
      toolName: "summarize_conversation",
      input: JSON.stringify({
        reason: "Context length exceeded, summarizing conversation to continue",
        messageCount: messages.length,
      }),
      result:
        "Conversation summarized successfully. Resuming with condensed context...",
    } as unknown as TextStreamPart<ToolSet>;
    yield toolResultEvent;

    // Now yield all events from the resumed stream
    // Note: resumedStream is already wrapped with error handling by streamResponse,
    // so if this also hits context limits, it will recursively summarize again
    for await (const chunk of resumedStream.fullStream) {
      yield chunk;
    }
  })();

  // Return a minimal StreamTextResult-like object with the wrapped stream
  // We delegate most properties to the resumed stream once it's available
  return {
    fullStream: wrappedFullStream,
    text: resumedStreamPromise.then((s) => s.text),
    content: resumedStreamPromise.then((s) => s.content),
    reasoning: resumedStreamPromise.then((s) => s.reasoning),
    reasoningText: resumedStreamPromise.then((s) => s.reasoningText),
    toolCalls: resumedStreamPromise.then((s) => s.toolCalls),
    toolResults: resumedStreamPromise.then((s) => s.toolResults),
    usage: resumedStreamPromise.then((s) => s.usage),
    finishReason: resumedStreamPromise.then((s) => s.finishReason),
    warnings: resumedStreamPromise.then((s) => s.warnings),
    response: resumedStreamPromise.then((s) => s.response),
    files: resumedStreamPromise.then((s) => s.files),
    sources: resumedStreamPromise.then((s) => s.sources),
    staticToolCalls: resumedStreamPromise.then((s) => s.staticToolCalls),
    dynamicToolCalls: resumedStreamPromise.then((s) => s.dynamicToolCalls),
    pipeTextStreamToResponse: async (response: unknown, init?: unknown) => {
      const stream = await resumedStreamPromise;
      return stream.pipeTextStreamToResponse(
        response as Parameters<
          StreamTextResult<ToolSet, never>["pipeTextStreamToResponse"]
        >[0],
        init as Parameters<
          StreamTextResult<ToolSet, never>["pipeTextStreamToResponse"]
        >[1],
      );
    },
    toDataStream: (_options?: unknown) => {
      throw new Error("toDataStream not supported on summarization stream");
    },
    toDataStreamResponse: (_options?: unknown) => {
      throw new Error(
        "toDataStreamResponse not supported on summarization stream",
      );
    },
  } as unknown as StreamTextResult<ToolSet, never>;
}

export async function consumeStream(
  stream: StreamTextResult<ToolSet, never>,
  {
    onTextDelta,
    onToolCallStreaming,
    onToolCallDelta,
    onToolCall,
    onToolResult,
  }: {
    onTextDelta?: (
      delta: Extract<TextStreamPart<ToolSet>, { type: "text-delta" }>,
    ) => void;
    onToolCallStreaming?: (delta: {
      toolCallId: string;
      toolName: string;
    }) => void;
    onToolCallDelta?: (delta: {
      toolCallId: string;
      argsTextDelta: string;
    }) => void;
    onToolCall?: (
      delta: Extract<TextStreamPart<ToolSet>, { type: "tool-call" }>,
    ) => void;
    onToolResult?: (
      delta: Extract<TextStreamPart<ToolSet>, { type: "tool-result" }>,
    ) => void;
  },
) {
  for await (const delta of stream.fullStream) {
    if (delta.type === "text-delta") {
      onTextDelta?.(delta);
    } else if (delta.type === "tool-input-start") {
      onToolCallStreaming?.({ toolCallId: delta.id, toolName: delta.toolName });
    } else if (delta.type === "tool-input-delta") {
      onToolCallDelta?.({ toolCallId: delta.id, argsTextDelta: delta.delta });
    } else if (delta.type === "tool-call") {
      onToolCall?.(delta);
    } else if (delta.type === "tool-result") {
      onToolResult?.(delta);
    }
  }
}
