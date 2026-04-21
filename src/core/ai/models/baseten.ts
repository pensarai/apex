// Curated manually — Baseten serves a custom set of models via an
// OpenAI-compatible endpoint. Add or remove models here as needed.

import type { ModelInfo } from "../ai";

export const BASETEN_MODELS: ModelInfo[] = [
  {
    id: "moonshotai/Kimi-K2.6",
    name: "Kimi K2.6",
    provider: "baseten",
    contextLength: 262144,
  },
];
