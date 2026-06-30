// Curated manually — Bedrock Mantle (OpenAI Responses API) models are not
// enumerated by the SDK type definitions.

import type { ModelInfo } from "../ai";

export const MANTLE_MODELS: ModelInfo[] = [
  {
    id: "mantle:openai.gpt-5.5",
    name: "GPT 5.5 (Bedrock Mantle)",
    provider: "bedrock-mantle",
    contextLength: 272000,
  },
];
