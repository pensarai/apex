import type { ModelInfo } from "../ai";

// Baseten is a model deployment platform where users deploy their own models.
// Model IDs are user-specific (deployment IDs).
// Users can add their deployed model IDs here or use them directly.
export const BASETEN_MODELS: ModelInfo[] = [
  {
    id: "zai-org/GLM-4.7",
    name: "GLM-4.7",
    provider: "baseten",
  },
];
