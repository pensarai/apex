import type { ModelInfo } from '../ai';
export const BEDROCK_MODELS: ModelInfo[] = [
  // Amazon Titan Models
  {
    id: 'amazon.titan-tg1-large',
    provider: 'bedrock',
    contextLength: 8000,
  },
  {
    id: 'amazon.titan-text-express-v1',
    provider: 'bedrock',
    contextLength: 8000,
  },
  {
    id: 'amazon.titan-text-lite-v1',
    provider: 'bedrock',
    contextLength: 4000,
  },
  {
    id: 'amazon.titan-text-premier-v1:0',
    provider: 'bedrock',
    contextLength: 32000,
  },

  // Anthropic Claude Models
  {
    id: 'anthropic.claude-v2',
    provider: 'bedrock',
    contextLength: 100000,
  },
  {
    id: 'anthropic.claude-v2:1',
    provider: 'bedrock',
    contextLength: 100000,
  },
  {
    id: 'anthropic.claude-instant-v1',
    provider: 'bedrock',
    contextLength: 100000,
  },
  {
    id: 'anthropic.claude-3-haiku-20240307-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-3-sonnet-20240229-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-3-opus-20240229-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-3-5-haiku-20241022-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-3-5-sonnet-20240620-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-3-7-sonnet-20250219-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-haiku-4-5-20251001-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-sonnet-4-20250514-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-sonnet-4-5-20250929-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-opus-4-20250514-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-opus-4-1-20250805-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },

  // Cohere Models
  {
    id: 'cohere.command-text-v14',
    provider: 'bedrock',
    contextLength: 4000,
  },
  {
    id: 'cohere.command-light-text-v14',
    provider: 'bedrock',
    contextLength: 4000,
  },
  {
    id: 'cohere.command-r-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'cohere.command-r-plus-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },

  // Meta Llama Models
  {
    id: 'meta.llama3-8b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 8000,
  },
  {
    id: 'meta.llama3-70b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 8000,
  },
  {
    id: 'meta.llama3-1-8b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'meta.llama3-1-70b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'meta.llama3-1-405b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'meta.llama3-2-1b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'meta.llama3-2-3b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'meta.llama3-2-11b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'meta.llama3-2-90b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },

  // Mistral Models
  {
    id: 'mistral.mistral-7b-instruct-v0:2',
    provider: 'bedrock',
    contextLength: 32000,
  },
  {
    id: 'mistral.mixtral-8x7b-instruct-v0:1',
    provider: 'bedrock',
    contextLength: 32000,
  },
  {
    id: 'mistral.mistral-small-2402-v1:0',
    provider: 'bedrock',
    contextLength: 32000,
  },
  {
    id: 'mistral.mistral-large-2402-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },

  // OpenAI Models on Bedrock
  {
    id: 'openai.gpt-oss-20b-1:0',
    provider: 'bedrock',
    contextLength: 8000,
  },
  {
    id: 'openai.gpt-oss-120b-1:0',
    provider: 'bedrock',
    contextLength: 8000,
  },

  // US Region - Amazon Nova Models
  {
    id: 'us.amazon.nova-micro-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.amazon.nova-lite-v1:0',
    provider: 'bedrock',
    contextLength: 300000,
  },
  {
    id: 'us.amazon.nova-pro-v1:0',
    provider: 'bedrock',
    contextLength: 300000,
  },
  {
    id: 'us.amazon.nova-premier-v1:0',
    provider: 'bedrock',
    contextLength: 300000,
  },

  // US Region - Anthropic Claude Models
  {
    id: 'us.anthropic.claude-3-haiku-20240307-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-3-sonnet-20240229-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-3-opus-20240229-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-3-5-haiku-20241022-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-3-5-sonnet-20240620-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-3-5-sonnet-20241022-v2:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-3-7-sonnet-20250219-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-sonnet-4-20250514-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-sonnet-4-5-20250929-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-opus-4-20250514-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-opus-4-1-20250805-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },

  // US Region - Meta Llama Models
  {
    id: 'us.meta.llama3-1-8b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama3-1-70b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama3-2-1b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama3-2-3b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama3-2-11b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama3-2-90b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama3-3-70b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama4-scout-17b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama4-maverick-17b-instruct-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },

  // US Region - Mistral Models
  {
    id: 'us.mistral.pixtral-large-2502-v1:0',
    provider: 'bedrock',
    contextLength: 128000,
  },

  // US Region - DeepSeek Models
  {
    id: 'us.deepseek.r1-v1:0',
    provider: 'bedrock',
    contextLength: 64000,
  },

  // Global Region - Anthropic Claude Models
  {
    id: 'global.anthropic.claude-haiku-4-5-20251001-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'global.anthropic.claude-sonnet-4-5-20250929-v1:0',
    provider: 'bedrock',
    contextLength: 200000,
  },
];
