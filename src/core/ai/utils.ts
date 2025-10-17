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

export function getProviderModel(model: AIModel): LanguageModel {
  const { provider } = getModelInfo(model);

  let providerModel;

  switch (provider) {
    case "openai":
      const openai = createOpenAI({
        apiKey: process.env.OPENAI_API_KEY,
      });
      providerModel = openai(model);
      break;

    case "openrouter":
      const openrouter = createOpenRouter({
        apiKey: process.env.OPENROUTER_API_KEY,
      });
      providerModel = openrouter(model);
      break;

    case "bedrock":
      const bedrock = createAmazonBedrock({
        region: process.env.AWS_REGION || "us-east-1",
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      });
      providerModel = bedrock(model);
      break;

    case "anthropic":
      providerModel = createAnthropic({
        apiKey: process.env.ANTHROPIC_API_KEY,
      }).chat(model);
      break;

    case "local":
      providerModel = createOpenAI({
        baseURL: process.env.LOCAL_MODEL_URL,
        apiKey: "",
      }).chat(model);
      break;

    default:
      const anthropic = createAnthropic({
        apiKey: process.env.ANTHROPIC_API_KEY,
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
  const slicedMessages = messages.slice(20);
  const { content: summary } = await generateText({
    model,
    system: `You are a helpful assistant that summarizes conversations to pass to another agent. Review the conversation and system prompt at the end provided by the user.`,
    messages: [
      ...slicedMessages,
      {
        role: "user",
        content: `Summarize this conversation to pass to another agent. This was the system prompt: ${opts.system} `,
      },
    ],
  });

  const enhancedPrompt = `${opts.prompt}\n\n The previous agent has summarized the conversation to pass to another you to coninue the task. Here is the summary: ${summary}`;
  const resumed = streamResponse({
    ...opts,
    prompt: enhancedPrompt,
    messages: undefined,
  });
  return resumed;
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
