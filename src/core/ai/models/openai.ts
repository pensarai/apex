import type { ModelInfo } from "../ai";
export const OPENAI_MODELS: ModelInfo[] = [
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
];
