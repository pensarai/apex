import type { ModelInfo } from "../ai";

export const ARCEE_MODELS: ModelInfo[] = [
  {
    id: "trinity-large-thinking",
    name: "Trinity Large Thinking",
    provider: "arcee",
    contextLength: 128_000,
  },
  {
    id: "trinity-large-preview",
    name: "Trinity Large (Preview)",
    provider: "arcee",
    contextLength: 128_000,
  },
  {
    id: "trinity-mini",
    name: "Trinity Mini",
    provider: "arcee",
    contextLength: 128_000,
  },
];
