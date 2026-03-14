import type { ModelInfo } from "../ai";

export const BASETEN_MODELS: ModelInfo[] = [
  {
    id: "baseten:huihui-ai/Huihui-Qwen3.5-35B-A3B-abliterated",
    name: "Huihui Qwen 3.5 35B A3B (Baseten)",
    provider: "baseten",
    contextLength: 128_000,
  },
  {
    id: "baseten:pensarai/qwen3.5-35b-abliterated-apex-sft-merged",
    name: "Pensarai Qwen 3.5 35B Apex SFT (Baseten)",
    provider: "baseten",
    contextLength: 128_000,
  },
];

export const BASETEN_MODEL_URLS: Record<string, string> = {
  "huihui-ai/Huihui-Qwen3.5-35B-A3B-abliterated":
    "https://model-3m54dgzw.api.baseten.co/environments/production/sync/v1",
  "pensarai/qwen3.5-35b-abliterated-apex-sft-merged":
    "https://model-wx4egp7q.api.baseten.co/environments/production/sync/v1",
};
