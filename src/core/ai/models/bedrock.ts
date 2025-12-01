import type { ModelInfo } from "../ai";
export const BEDROCK_MODELS: ModelInfo[] = [
  // Amazon Bedrock Models
  // Anthropic Claude Models
  {
    id: "anthropic.claude-3-haiku-20240307-v1:0",
    name: "Claude 3 Haiku (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
  {
    id: "anthropic.claude-3-5-haiku-20241022-v1:0",
    name: "Claude 3.5 Haiku (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
  {
    id: "anthropic.claude-3-7-sonnet-20250219-v1:0",
    name: "Claude 3.7 Sonnet (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
  {
    id: "anthropic.claude-haiku-4-5-20251001-v1:0",
    name: "Claude Haiku 4.5 (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
  {
    id: "anthropic.claude-opus-4-1-20250805-v1:0",
    name: "Claude Opus 4.1 (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
  {
    id: "anthropic.claude-opus-4-5-20251101-v1:0",
    name: "Claude Opus 4.5 (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
  {
    id: "anthropic.claude-opus-4-20250514-v1:0",
    name: "Claude Opus 4 (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
  {
    id: "anthropic.claude-sonnet-4-5-20250929-v1:0",
    name: "Claude Sonnet 4.5 (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
  {
    id: "anthropic.claude-sonnet-4-20250514-v1:0",
    name: "Claude Sonnet 4 (Bedrock)",
    provider: "bedrock",
    contextLength: 200000,
  },
  {
    id: "amazon.titan-text-premier-v1:0",
    name: "Amazon Titan Text Premier",
    provider: "bedrock",
    contextLength: 32000,
  },
  {
    id: "amazon.titan-text-express-v1",
    name: "Amazon Titan Text Express",
    provider: "bedrock",
    contextLength: 8000,
  },
  {
    id: "meta.llama3-1-405b-instruct-v1:0",
    name: "Llama 3.1 405B (Bedrock)",
    provider: "bedrock",
    contextLength: 128000,
  },
  {
    id: "meta.llama3-1-70b-instruct-v1:0",
    name: "Llama 3.1 70B (Bedrock)",
    provider: "bedrock",
    contextLength: 128000,
  },
  {
    id: "meta.llama3-1-8b-instruct-v1:0",
    name: "Llama 3.1 8B (Bedrock)",
    provider: "bedrock",
    contextLength: 128000,
  },
  {
    id: "mistral.mistral-large-2407-v1:0",
    name: "Mistral Large (Bedrock)",
    provider: "bedrock",
    contextLength: 128000,
  },
];
