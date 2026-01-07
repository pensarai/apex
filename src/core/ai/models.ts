import type { AIModel, ModelInfo } from "./ai";

export const AVAILABLE_MODELS: ModelInfo[] = [
  // Anthropic Models
  {
    id: "claude-haiku-4-5",
    name: "Claude Haiku 4.5",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-sonnet-4-5",
    name: "Claude Sonnet 4.5",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "claude-opus-4-5",
    name: "Claude Opus 4.5",
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
    id: "gpt-4o-mini",
    name: "GPT-4o Mini",
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
    id: "anthropic/claude-haiku-4.5",
    name: "Claude Haiku 4.5 (OpenRouter)",
    provider: "openrouter",
    contextLength: 200000,
  },
  {
    id: "anthropic/claude-sonnet-4.5",
    name: "Claude Sonnet 4.5 (OpenRouter)",
    provider: "openrouter",
    contextLength: 200000,
  },
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
    id: "anthropic/claude-opus-4.5",
    name: "Claude Opus 4.5 (OpenRouter)",
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
    id: "google/gemini-3-pro-preview",
    name: "Gemini 3 Pro Preview",
    provider: "openrouter",
    contextLength: 1000000,
  },
  {
    id: "nvidia/nemotron-3-nano-30b-a3b:free",
    name: "Nemotron 3 Nano 30B A3B (Free)",
    provider: "openrouter",
    contextLength: 256000,
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
    id: "qwen/qwen3-8b",
    name: "Qwen 3 8B Thinking",
    provider: "openrouter",
    contextLength: 256000,
  },
  {
    id: "qwen/qwen3-14b",
    name: "Qwen 3 14B Instruct",
    provider: "openrouter",
    contextLength: 256000,
  },
  {
    id: "qwen/qwen3-32b",
    name: "Qwen 3 32B Instruct",
    provider: "openrouter",
    contextLength: 256000,
  },
  {
    id: "qwen/qwen3-30b-a3b-thinking-2507",
    name: "Qwen 3 30B A3B Thinking",
    provider: "openrouter",
    contextLength: 32768,
  },
  {
    id: "arcee-ai/trinity-mini:free",
    name: "Arcee Trinity Mini (Free)",
    provider: "openrouter",
    contextLength: 131072,
  },
  {
    id: "arcee-ai/trinity-mini",
    name: "Arcee Trinity Mini",
    provider: "openrouter",
    contextLength: 131072,
  },
  {
    id: "x-ai/grok-4.1-fast:free",
    name: "Grok 4.1 Fast (Free)",
    provider: "openrouter",
    contextLength: 2000000,
  },
  // Amazon Bedrock Models
  {
    id: "global.anthropic.claude-haiku-4-5-20251001-v1:0",
    name: "Claude Haiku 4.5 (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
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

export function getModelInfo(model: AIModel): ModelInfo {
  return (
    AVAILABLE_MODELS.find((m) => m.id === model) ?? {
      id: model,
      name: model,
      provider: "local",
    }
  );
}
