import type { ModelInfo } from "../ai";

// Curated from Concentrate's public model catalog. The local prefix keeps
// gateway selections distinct from direct-provider models and is not sent.
export const CONCENTRATE_MODELS: ModelInfo[] = [
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
    id: "concentrate:glm-5",
    name: "GLM-5",
    provider: "concentrate",
    contextLength: 202800,
  },
];
