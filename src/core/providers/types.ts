export type ProviderType = "anthropic" | "openai" | "bedrock" | "openrouter";

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
    id: "openrouter",
    name: "OpenRouter",
    description: "Access multiple AI models through one API",
    requiresAPIKey: true,
  },
  {
    id: "bedrock",
    name: "AWS Bedrock",
    description: "Amazon Bedrock AI models",
    requiresAPIKey: true,
  },
];
