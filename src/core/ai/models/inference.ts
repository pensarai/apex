import type { ModelInfo } from "../ai";

// Limits from https://api.inference.net/v1/models.
export const INFERENCE_MODELS: ModelInfo[] = [
  {
    id: "inference:deepseek-v4.1-flash-1017-cyber",
    name: "DeepSeek V4.1 Flash 1017 Cyber",
    provider: "inference",
    contextLength: 1_040_000,
  },
];
