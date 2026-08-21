export type ProviderType =
  | "anthropic"
  | "openai"
  | "google"
  | "bedrock"
  | "openrouter"
  | "concentrate"
  | "inception"
  | "pensar"
  | "local";

export interface Provider {
  id: ProviderType;
  name: string;
  description: string;
  requiresAPIKey: boolean;
  icon?: string;
}

export interface ConfiguredProvider extends Provider {
  configured: boolean;
  hasValidKey: boolean;
}

export const AVAILABLE_PROVIDERS: Provider[] = [
  {
    id: "anthropic",
    name: "Anthropic",
    description: "Claude Pro/Max or API key",
    requiresAPIKey: true,
  },
  {
    id: "openai",
    name: "OpenAI",
    description: "GPT-4 and other OpenAI models",
    requiresAPIKey: true,
  },
  {
    id: "google",
    name: "Google",
    description: "Gemini and other Google AI models",
    requiresAPIKey: true,
  },
  {
    id: "openrouter",
    name: "OpenRouter",
    description: "Access multiple AI models through one API",
    requiresAPIKey: true,
  },
  {
    id: "concentrate",
    name: "Concentrate",
    description: "Access multiple AI models through one API",
    requiresAPIKey: true,
  },
  {
    id: "inception",
    name: "Inception",
    description: "Mercury and other Inception models",
    requiresAPIKey: true,
  },
  {
    id: "bedrock",
    name: "AWS Bedrock",
    description: "Amazon Bedrock AI models",
    requiresAPIKey: true,
  },
  {
    id: "local",
    name: "Local LLM",
    description: "OpenAI-compatible local model (vLLM, LM Studio, Ollama)",
    requiresAPIKey: false,
  },
  {
    id: "pensar",
    name: "Pensar",
    description: "Managed inference via Pensar Console (usage-based billing)",
    requiresAPIKey: false,
  },
];
