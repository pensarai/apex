import type { ModelInfo } from "../ai";
export const OPENROUTER_MODELS: ModelInfo[] = [
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
];
