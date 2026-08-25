import type { AIModelProvider, ModelInfo } from "../../../core/ai";

// Lifecycle status is provider-specific; gateway and local models are intentionally unaffected.
const HIDDEN_MODEL_IDS: Partial<Record<AIModelProvider, ReadonlySet<string>>> =
  {
    anthropic: new Set([
      "claude-3-haiku-20240307",
      "claude-opus-4-0",
      "claude-opus-4-20250514",
      "claude-opus-4-1",
      "claude-opus-4-1-20250805",
      "claude-sonnet-4-0",
      "claude-sonnet-4-20250514",
    ]),
    openai: new Set([
      "gpt-5.3-chat-latest",
      "gpt-5.2-chat-latest",
      "gpt-5.2-codex",
      "gpt-5.1-chat-latest",
      "gpt-5.1-codex-mini",
      "gpt-5.1-codex",
      "gpt-5.1-codex-max",
      "gpt-5-chat-latest",
      "gpt-5-codex",
      "gpt-4.1-nano",
      "gpt-4.1-nano-2025-04-14",
      "gpt-3.5-turbo",
      "gpt-3.5-turbo-0125",
      "gpt-3.5-turbo-1106",
      "o4-mini",
      "o4-mini-2025-04-16",
      "o3-mini",
      "o3-mini-2025-01-31",
      "o1",
      "o1-2024-12-17",
    ]),
    google: new Set([
      "gemini-2.0-flash",
      "gemini-2.0-flash-001",
      "gemini-2.0-flash-lite",
      "gemini-2.0-flash-lite-001",
      "gemini-3-pro-preview",
      "gemini-3.1-flash-lite-preview",
      "gemini-robotics-er-1.5-preview",
    ]),
  };

export function getVisiblePickerModels(
  models: readonly ModelInfo[],
): ModelInfo[] {
  return models.filter(
    (model) => !HIDDEN_MODEL_IDS[model.provider]?.has(model.id),
  );
}
