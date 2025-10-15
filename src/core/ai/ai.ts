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

export const AVAILABLE_MODELS: ModelInfo[] = [
  // Anthropic Models
  {
    id: "claude-sonnet-4-5",
    name: "Claude Sonnet 4.5",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-sonnet-4-5-20250929",
    name: "Claude Sonnet 4.5 (2025-09-29)",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-opus-4-1",
    name: "Claude Opus 4.1",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-opus-4-1-20250805",
    name: "Claude Opus 4.1 (2025-08-05)",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-opus-4-0",
    name: "Claude Opus 4.0",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-opus-4-20250514",
    name: "Claude Opus 4 (2025-05-14)",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-sonnet-4-0",
    name: "Claude Sonnet 4.0",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-sonnet-4-20250514",
    name: "Claude Sonnet 4 (2025-05-14)",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-3-7-sonnet-latest",
    name: "Claude 3.7 Sonnet (Latest)",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-3-7-sonnet-20250219",
    name: "Claude 3.7 Sonnet (2025-02-19)",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-3-5-haiku-latest",
    name: "Claude 3.5 Haiku (Latest)",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-3-5-haiku-20241022",
    name: "Claude 3.5 Haiku (2024-10-22)",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-3-haiku-20240307",
    name: "Claude 3 Haiku (2024-03-07)",
    provider: "anthropic",
    contextLength: 200000,
  },

  // OpenAI Models
  {
    id: "gpt-4.5-turbo",
    name: "GPT-4.5 Turbo",
    provider: "openai",
    contextLength: 128000,
  },
  {
    id: "gpt-4o",
    name: "GPT-4o",
    provider: "openai",
    contextLength: 128000,
  },
  {
    id: "gpt-4o-mini",
    name: "GPT-4o Mini",
    provider: "openai",
    contextLength: 128000,
  },
  {
    id: "gpt-4-turbo",
    name: "GPT-4 Turbo",
    provider: "openai",
    contextLength: 128000,
  },
  {
    id: "gpt-4",
    name: "GPT-4",
    provider: "openai",
    contextLength: 8192,
  },
  {
    id: "gpt-3.5-turbo",
    name: "GPT-3.5 Turbo",
    provider: "openai",
    contextLength: 16385,
  },
  {
    id: "o1",
    name: "O1",
    provider: "openai",
    contextLength: 200000,
  },
  {
    id: "o1-mini",
    name: "O1 Mini",
    provider: "openai",
    contextLength: 128000,
  },

  // OpenRouter Models
  {
    id: "anthropic/claude-sonnet-4",
    name: "Claude Sonnet 4 (OpenRouter)",
    provider: "openrouter",
    contextLength: 200000,
  },
  {
    id: "anthropic/claude-opus-4",
    name: "Claude Opus 4 (OpenRouter)",
    provider: "openrouter",
    contextLength: 200000,
  },
  {
    id: "anthropic/claude-3.5-sonnet",
    name: "Claude 3.5 Sonnet (OpenRouter)",
    provider: "openrouter",
    contextLength: 200000,
  },
  {
    id: "openai/gpt-4o",
    name: "GPT-4o (OpenRouter)",
    provider: "openrouter",
    contextLength: 128000,
  },
  {
    id: "openai/gpt-4o-mini",
    name: "GPT-4o Mini (OpenRouter)",
    provider: "openrouter",
    contextLength: 128000,
  },
  {
    id: "openai/o1",
    name: "O1 (OpenRouter)",
    provider: "openrouter",
    contextLength: 200000,
  },
  {
    id: "google/gemini-2.0-flash-exp:free",
    name: "Gemini 2.0 Flash Exp (Free)",
    provider: "openrouter",
    contextLength: 1000000,
  },
  {
    id: "google/gemini-2.0-flash-thinking-exp:free",
    name: "Gemini 2.0 Flash Thinking (Free)",
    provider: "openrouter",
    contextLength: 32768,
  },
  {
    id: "google/gemini-pro-1.5",
    name: "Gemini Pro 1.5",
    provider: "openrouter",
    contextLength: 2000000,
  },
  {
    id: "meta-llama/llama-3.3-70b-instruct",
    name: "Llama 3.3 70B Instruct",
    provider: "openrouter",
    contextLength: 128000,
  },
  {
    id: "meta-llama/llama-3.1-405b-instruct",
    name: "Llama 3.1 405B Instruct",
    provider: "openrouter",
    contextLength: 128000,
  },
  {
    id: "deepseek/deepseek-chat",
    name: "DeepSeek Chat",
    provider: "openrouter",
    contextLength: 64000,
  },
  {
    id: "deepseek/deepseek-r1",
    name: "DeepSeek R1",
    provider: "openrouter",
    contextLength: 64000,
  },
  {
    id: "qwen/qwen-2.5-coder-32b-instruct",
    name: "Qwen 2.5 Coder 32B",
    provider: "openrouter",
    contextLength: 32768,
  },
  {
    id: "qwen/qwq-32b-preview",
    name: "QwQ 32B Preview",
    provider: "openrouter",
    contextLength: 32768,
  },
  {
    id: "moonshot/kimi-k2-turbo",
    name: "Kimi K2 Turbo",
    provider: "openrouter",
    contextLength: 128000,
  },
  {
    id: "moonshot/kimi-k2-chat",
    name: "Kimi K2 Chat",
    provider: "openrouter",
    contextLength: 128000,
  },
  {
    id: "mistralai/codestral-latest",
    name: "Codestral Latest",
    provider: "openrouter",
    contextLength: 32000,
  },
  {
    id: "mistralai/mistral-large",
    name: "Mistral Large",
    provider: "openrouter",
    contextLength: 128000,
  },
  {
    id: "x-ai/grok-2",
    name: "Grok 2",
    provider: "openrouter",
    contextLength: 131072,
  },
  {
    id: "x-ai/grok-2-vision",
    name: "Grok 2 Vision",
    provider: "openrouter",
    contextLength: 32768,
  },

  // Amazon Bedrock Models
  {
    id: "anthropic.claude-3-5-sonnet-20240620-v1:0",
    name: "Claude 3.5 Sonnet (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
  {
    id: "anthropic.claude-3-opus-20240229-v1:0",
    name: "Claude 3 Opus (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
  {
    id: "anthropic.claude-3-sonnet-20240229-v1:0",
    name: "Claude 3 Sonnet (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
  {
    id: "anthropic.claude-3-haiku-20240307-v1:0",
    name: "Claude 3 Haiku (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
  {
    id: "amazon.titan-text-premier-v1:0",
    name: "Amazon Titan Text Premier",
    provider: "bedrock",
    contextLength: 32000,
  },
  {
    id: "amazon.titan-text-express-v1",
    name: "Amazon Titan Text Express",
    provider: "bedrock",
    contextLength: 8000,
  },
  {
    id: "meta.llama3-1-405b-instruct-v1:0",
    name: "Llama 3.1 405B (Bedrock)",
    provider: "bedrock",
    contextLength: 128000,
  },
  {
    id: "meta.llama3-1-70b-instruct-v1:0",
    name: "Llama 3.1 70B (Bedrock)",
    provider: "bedrock",
    contextLength: 128000,
  },
  {
    id: "meta.llama3-1-8b-instruct-v1:0",
    name: "Llama 3.1 8B (Bedrock)",
    provider: "bedrock",
    contextLength: 128000,
  },
  {
    id: "mistral.mistral-large-2407-v1:0",
    name: "Mistral Large (Bedrock)",
    provider: "bedrock",
    contextLength: 128000,
  },
];

export interface GetResponseProps {
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
  opts: GetResponseProps
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

  // Find the model info to determine the provider
  const modelInfo = AVAILABLE_MODELS.find((m) => m.id === model);

  const provider = modelInfo?.provider ?? "local";

  // Create the appropriate provider instance
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

  const response = streamText({
    model: providerModel,
    system,
    ...(messages ? { messages } : { prompt }),
    stopWhen,
    toolChoice,
    tools,
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
