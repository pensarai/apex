import type { ModelInfo } from "../ai";

// Concentrate does not route on max_output_tokens, so these use the lowest
// ceiling among each slug's upstream providers.
export const CONCENTRATE_MAX_OUTPUT_TOKENS: Readonly<Record<string, number>> = {
  "concentrate:kimi-k3": 32_768,
  "concentrate:kimi-k3-1-pro": 32_768,
  "concentrate:qwen3.8-max": 32_768,
  "concentrate:qwen3.8-27b": 32_768,
  "concentrate:deepseek-v4-1-flash": 32_768,
  "concentrate:deepseek-v4-1-flash-1017": 131_072,
};

// Curated from Concentrate's public model catalog. The local prefix keeps
// gateway selections distinct from direct-provider models and is not sent.
export const CONCENTRATE_MODELS: ModelInfo[] = [
  {
    id: "concentrate:claude-sonnet-5-5",
    name: "Claude Sonnet 5.5",
    provider: "concentrate",
    contextLength: 1000000,
  },
  {
    id: "concentrate:claude-opus-5-5",
    name: "Claude Opus 5.5",
    provider: "concentrate",
    contextLength: 1000000,
  },
  {
    id: "concentrate:claude-fable-5-1",
    name: "Claude Fable 5.1",
    provider: "concentrate",
    contextLength: 1000000,
  },
  {
    id: "concentrate:claude-opus-5",
    name: "Claude Opus 5",
    provider: "concentrate",
    contextLength: 1000000,
  },
  {
    id: "concentrate:claude-sonnet-5",
    name: "Claude Sonnet 5",
    provider: "concentrate",
    contextLength: 1000000,
  },
  {
    id: "concentrate:claude-fable-5",
    name: "Claude Fable 5",
    provider: "concentrate",
    contextLength: 1000000,
  },
  {
    id: "concentrate:gpt-6.1-sol",
    name: "GPT-6.1 Sol",
    provider: "concentrate",
    contextLength: 1050000,
  },
  {
    id: "concentrate:gpt-6.1-terra",
    name: "GPT 6.1 Terra",
    provider: "concentrate",
    contextLength: 1050000,
  },
  {
    id: "concentrate:gpt-6-luna",
    name: "GPT-6 Luna",
    provider: "concentrate",
    contextLength: 1050000,
  },
  {
    id: "concentrate:gpt-6-sol",
    name: "GPT-6 Sol",
    provider: "concentrate",
    contextLength: 1050000,
  },
  {
    id: "concentrate:gpt-6-astra",
    name: "GPT-6 Astra",
    provider: "concentrate",
    contextLength: 1050000,
  },
  {
    id: "concentrate:gpt-5.4-nano",
    name: "GPT-5.4 Nano",
    provider: "concentrate",
    contextLength: 400000,
  },
  {
    id: "concentrate:gpt-5.4-mini",
    name: "GPT-5.4 Mini",
    provider: "concentrate",
    contextLength: 400000,
  },
  {
    id: "concentrate:claude-opus-4-6",
    name: "Claude Opus 4.6",
    provider: "concentrate",
    contextLength: 200000,
  },
  {
    id: "concentrate:claude-sonnet-4-6",
    name: "Claude Sonnet 4.6",
    provider: "concentrate",
    contextLength: 200000,
  },
  {
    id: "concentrate:claude-sonnet-4-5",
    name: "Claude Sonnet 4.5",
    provider: "concentrate",
    contextLength: 200000,
  },
  {
    id: "concentrate:claude-haiku-4-5",
    name: "Claude Haiku 4.5",
    provider: "concentrate",
    contextLength: 200000,
  },
  {
    id: "concentrate:gpt-5.6-sol",
    name: "GPT 5.6 Sol",
    provider: "concentrate",
    contextLength: 1050000,
  },
  {
    id: "concentrate:gpt-5.6-terra",
    name: "GPT 5.6 Terra",
    provider: "concentrate",
    contextLength: 1050000,
  },
  {
    id: "concentrate:gpt-5.6-luna",
    name: "GPT 5.6 Luna",
    provider: "concentrate",
    contextLength: 1050000,
  },
  {
    id: "concentrate:gpt-5.5",
    name: "GPT 5.5",
    provider: "concentrate",
    contextLength: 1050000,
  },
  {
    id: "concentrate:gpt-5.4",
    name: "GPT 5.4",
    provider: "concentrate",
    contextLength: 1050000,
  },
  {
    id: "concentrate:gpt-5.3-codex",
    name: "GPT 5.3 Codex",
    provider: "concentrate",
    contextLength: 400000,
  },
  {
    id: "concentrate:gemini-3.6-flash",
    name: "Gemini 3.6 Flash",
    provider: "concentrate",
    contextLength: 1048576,
  },
  {
    id: "concentrate:gemini-3.1-pro-preview",
    name: "Gemini 3.1 Pro Preview",
    provider: "concentrate",
    contextLength: 1000000,
  },
  {
    id: "concentrate:gemini-2.5-pro",
    name: "Gemini 2.5 Pro",
    provider: "concentrate",
    contextLength: 1000000,
  },
  {
    id: "concentrate:qwen3.8-max",
    name: "Qwen3.8 Max",
    provider: "concentrate",
    contextLength: 256000,
  },
  {
    id: "concentrate:qwen3.8-27b",
    name: "Qwen3.8 27B",
    provider: "concentrate",
    contextLength: 262144,
  },
  {
    id: "concentrate:deepseek-v4-1-flash-1017",
    name: "DeepSeek V4.1 Flash 1017",
    provider: "concentrate",
    contextLength: 1048576,
  },
  {
    id: "concentrate:deepseek-v4-1-flash",
    name: "DeepSeek V4.1 Flash",
    provider: "concentrate",
    contextLength: 1000000,
  },
  {
    id: "concentrate:deepseek-v4-pro-0813",
    name: "DeepSeek V4 Pro 0813",
    provider: "concentrate",
    contextLength: 1048576,
  },
  {
    id: "concentrate:deepseek-v3-2",
    name: "DeepSeek V3.2",
    provider: "concentrate",
    contextLength: 163840,
  },
  {
    id: "concentrate:mistral-large-3",
    name: "Mistral Large 3",
    provider: "concentrate",
    contextLength: 256000,
  },
  {
    id: "concentrate:kimi-k3",
    name: "Kimi K3",
    provider: "concentrate",
    contextLength: 1048576,
  },
  {
    id: "concentrate:kimi-k3-1-pro",
    name: "Kimi K3.1 Pro",
    provider: "concentrate",
    contextLength: 1048576,
  },
  {
    id: "concentrate:kimi-k2-thinking",
    name: "Kimi K2 Thinking",
    provider: "concentrate",
    contextLength: 262144,
  },
  {
    id: "concentrate:minimax-m2-7",
    name: "MiniMax M2.7",
    provider: "concentrate",
    contextLength: 204800,
  },
  {
    id: "concentrate:mimo-v2.6-pro",
    name: "MiMo V2.6 Pro",
    provider: "concentrate",
    contextLength: 1048576,
  },
  {
    id: "concentrate:glm-5.3",
    name: "GLM-5.3",
    provider: "concentrate",
    contextLength: 1048576,
  },
  {
    id: "concentrate:glm-5",
    name: "GLM-5",
    provider: "concentrate",
    contextLength: 202800,
  },
];
