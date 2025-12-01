import { createOpenAI } from "@ai-sdk/openai";
import { streamResponse, type AIModel, type StreamResponseOpts } from "./ai";
import { createOpenRouter } from "@openrouter/ai-sdk-provider";
import { createAmazonBedrock } from "@ai-sdk/amazon-bedrock";
import { createAnthropic } from "@ai-sdk/anthropic";
import { getModelInfo } from "./models";
import {
  generateText,
  type LanguageModel,
  type ModelMessage,
  type StreamTextResult,
  type TextStreamPart,
  type ToolSet,
} from "ai";

export type AIAuthConfig = {
  openAiAPIKey?: string;
  anthropicAPIKey?: string;
  openRouterAPIKey?: string;
  bedrock?: {
    enabled?: boolean;
    accessKeyId?: string;
    secretAccessKey?: string;
    region?: string;
  };
  local?: {
    baseURL: string;
  };
};

export function getProviderModel(
  model: AIModel,
  authConfig?: AIAuthConfig
): LanguageModel {
  const { provider } = getModelInfo(model);

  const openAiAPIKey = authConfig?.openAiAPIKey || process.env.OPENAI_API_KEY;
  const anthropicAPIKey =
    authConfig?.anthropicAPIKey || process.env.ANTHROPIC_API_KEY;
  const openRouterAPIKey =
    authConfig?.openRouterAPIKey || process.env.OPENROUTER_API_KEY;
  const bedrockAccessKeyId =
    authConfig?.bedrock?.accessKeyId || process.env.AWS_ACCESS_KEY_ID;
  const bedrockSecretAccessKey =
    authConfig?.bedrock?.secretAccessKey || process.env.AWS_SECRET_ACCESS_KEY;
  const bedrockRegion = authConfig?.bedrock?.region || process.env.AWS_REGION;
  const localBaseURL =
    authConfig?.local?.baseURL ||
    process.env.LOCAL_MODEL_URL ||
    "http://127.0.0.1:1234/v1";

  let providerModel;

  switch (provider) {
    case "openai":
      const openai = createOpenAI({
        apiKey: openAiAPIKey,
      });
      providerModel = openai(model);
      break;

    case "openrouter":
      const openrouter = createOpenRouter({
        apiKey: openRouterAPIKey,
      });
      providerModel = openrouter(model);
      break;

    case "bedrock":
      const bedrock = createAmazonBedrock({
        region: bedrockRegion,
        accessKeyId: bedrockAccessKeyId,
        secretAccessKey: bedrockSecretAccessKey,
      });
      providerModel = bedrock(model);
      break;

    case "anthropic":
      providerModel = createAnthropic({
        apiKey: anthropicAPIKey,
      }).chat(model);
      break;

    case "local":
      providerModel = createOpenAI({
        baseURL: localBaseURL,
        apiKey: "",
      }).chat(model);
      break;

    default:
      const anthropic = createAnthropic({
        apiKey: anthropicAPIKey,
      });
      providerModel = anthropic(model);
      break;
  }

  return providerModel;
}

export async function summarizeConversation(
  messages: ModelMessage[],
  opts: StreamResponseOpts,
  model: LanguageModel
): Promise<StreamTextResult<ToolSet, never>> {
  // Filter and clean messages to remove tool calls/results
  // We only want conversational content for summarization
  const cleanMessages = messages
    .map((msg) => {
      // If content is an array, filter out tool-use and tool-result blocks
      if (Array.isArray(msg.content)) {
        const textContent = msg.content
          .filter((part: any) => part.type === "text")
          .map((part: any) => part.text)
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

  const { text: summary } = await generateText({
    model,
    system: `You are a helpful assistant that summarizes conversations to pass to another agent. Review the conversation and system prompt at the end provided by the user.`,
    messages: summarizedMessages,
  });

  // For very long prompts, replace with just the summary instead of appending
  const originalLength =
    typeof opts.prompt === "string" ? opts.prompt.length : 0;
  const enhancedPrompt =
    originalLength > 100000
      ? `Context: The previous conversation contained very long content that was summarized.\n\nSummary: ${summary}\n\nOriginal task: Please respond based on this summary.`
      : `${opts.prompt}\n\nThe previous agent has summarized the conversation to pass to you to continue the task. Here is the summary: ${summary}`;
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
export function checkIfContextLengthError(error: any): boolean {
  const errorMessage = error?.message?.toLowerCase() || "";
  const errorCode = String(error?.code || "").toLowerCase();

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
  model: LanguageModel
): StreamTextResult<ToolSet, never> {
  // Generate a unique tool call ID
  const toolCallId = `summarize-${Date.now()}`;

  // We need to handle this asynchronously but return synchronously
  // Create a promise that will hold the resumed stream
  let resumedStreamPromise: Promise<StreamTextResult<ToolSet, never>>;

  // Start the summarization process
  resumedStreamPromise = summarizeConversation(messages, opts, model);

  // Create a custom async generator that wraps the resumed stream
  const wrappedFullStream = (async function* () {
    // First, emit a synthetic tool-call event
    const toolCallEvent: any = {
      type: "tool-call",
      toolCallId,
      toolName: "summarize_conversation",
      input: JSON.stringify({
        reason: "Context length exceeded, summarizing conversation to continue",
        messageCount: messages.length,
      }),
    };
    yield toolCallEvent;

    // Wait for the summarization to complete
    const resumedStream = await resumedStreamPromise;

    // Emit a synthetic tool-result event
    const toolResultEvent: any = {
      type: "tool-result",
      toolCallId,
      toolName: "summarize_conversation",
      input: JSON.stringify({
        reason: "Context length exceeded, summarizing conversation to continue",
        messageCount: messages.length,
      }),
      result:
        "Conversation summarized successfully. Resuming with condensed context...",
    };
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
    pipeTextStreamToResponse: async (response: any, init?: any) => {
      const stream = await resumedStreamPromise;
      return stream.pipeTextStreamToResponse(response, init);
    },
    toDataStream: (options?: any) => {
      throw new Error("toDataStream not supported on summarization stream");
    },
    toDataStreamResponse: (options?: any) => {
      throw new Error(
        "toDataStreamResponse not supported on summarization stream"
      );
    },
  } as unknown as StreamTextResult<ToolSet, never>;
}

export async function consumeStream(
  stream: StreamTextResult<ToolSet, never>,
  {
    onTextDelta,
    onToolCall,
    onToolResult,
  }: {
    onTextDelta?: (
      delta: Extract<TextStreamPart<ToolSet>, { type: "text-delta" }>
    ) => void;
    onToolCall?: (
      delta: Extract<TextStreamPart<ToolSet>, { type: "tool-call" }>
    ) => void;
    onToolResult?: (
      delta: Extract<TextStreamPart<ToolSet>, { type: "tool-result" }>
    ) => void;
  }
) {
  for await (const delta of stream.fullStream) {
    if (delta.type === "text-delta") {
      onTextDelta?.(delta);
    } else if (delta.type === "tool-call") {
      onToolCall?.(delta);
    } else if (delta.type === "tool-result") {
      onToolResult?.(delta);
    }
  }
}
