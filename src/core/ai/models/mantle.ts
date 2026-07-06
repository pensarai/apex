// Curated manually — Bedrock Mantle (OpenAI Responses API) models are not
// enumerated by the SDK type definitions.

import type { ModelInfo } from "../ai";
import { MANTLE_GPT_5_5_ROUTED_ID } from "../mantle";

export const MANTLE_MODELS: ModelInfo[] = [
  {
    id: MANTLE_GPT_5_5_ROUTED_ID,
    name: "GPT 5.5 (Bedrock Mantle)",
    provider: "bedrock-mantle",
    contextLength: 272000,
  },
];
