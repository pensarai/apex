// Curated manually — Bedrock Mantle (OpenAI Responses API) models are not
// enumerated by the SDK type definitions.

import type { ModelInfo } from "../ai";
import { MANTLE_GPT_5_5_ROUTED_ID } from "../mantle";

export const MANTLE_MODELS: ModelInfo[] = [
  {
    id: "mantle:openai.gpt-6-luna",
    name: "GPT-6 Luna (Bedrock Mantle)",
    provider: "bedrock-mantle",
    contextLength: 1050000,
  },
  {
    id: "mantle:openai.gpt-6-sol",
    name: "GPT-6 Sol (Bedrock Mantle)",
    provider: "bedrock-mantle",
    contextLength: 1050000,
  },
  {
    id: "mantle:openai.gpt-6-astra",
    name: "GPT-6 Astra (Bedrock Mantle)",
    provider: "bedrock-mantle",
    contextLength: 1050000,
  },
  {
    id: MANTLE_GPT_5_5_ROUTED_ID,
    name: "GPT 5.5 (Bedrock Mantle)",
    provider: "bedrock-mantle",
    contextLength: 272000,
  },
];
