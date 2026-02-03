import type { ModelInfo } from '../ai';
export const BEDROCK_MODELS: ModelInfo[] = [
  // Amazon Titan Models
  {
    id: 'amazon.titan-tg1-large',
    name: 'Amazon Titan TG1 Large',
    provider: 'bedrock',
    contextLength: 8000,
  },
  {
    id: 'amazon.titan-text-express-v1',
    name: 'Amazon Titan Text Express',
    provider: 'bedrock',
    contextLength: 8000,
  },
  {
    id: 'amazon.titan-text-lite-v1',
    name: 'Amazon Titan Text Lite',
    provider: 'bedrock',
    contextLength: 4000,
  },
  {
    id: 'amazon.titan-text-premier-v1:0',
    name: 'Amazon Titan Text Premier',
    provider: 'bedrock',
    contextLength: 32000,
  },

  // Anthropic Claude Models
  {
    id: 'anthropic.claude-v2',
    name: 'Claude v2 (Bedrock)',
    provider: 'bedrock',
    contextLength: 100000,
  },
  {
    id: 'anthropic.claude-v2:1',
    name: 'Claude v2.1 (Bedrock)',
    provider: 'bedrock',
    contextLength: 100000,
  },
  {
    id: 'anthropic.claude-instant-v1',
    name: 'Claude Instant v1 (Bedrock)',
    provider: 'bedrock',
    contextLength: 100000,
  },
  {
    id: 'anthropic.claude-3-haiku-20240307-v1:0',
    name: 'Claude 3 Haiku (Bedrock)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-3-sonnet-20240229-v1:0',
    name: 'Claude 3 Sonnet (Bedrock)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-3-opus-20240229-v1:0',
    name: 'Claude 3 Opus (Bedrock)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-3-5-haiku-20241022-v1:0',
    name: 'Claude 3.5 Haiku (Bedrock)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-3-5-sonnet-20240620-v1:0',
    name: 'Claude 3.5 Sonnet (Bedrock)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
    name: 'Claude 3.5 Sonnet v2 (Bedrock)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-3-7-sonnet-20250219-v1:0',
    name: 'Claude 3.7 Sonnet (Bedrock)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-haiku-4-5-20251001-v1:0',
    name: 'Claude Haiku 4.5 (Bedrock)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-sonnet-4-20250514-v1:0',
    name: 'Claude Sonnet 4 (Bedrock)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-sonnet-4-5-20250929-v1:0',
    name: 'Claude Sonnet 4.5 (Bedrock)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-opus-4-20250514-v1:0',
    name: 'Claude Opus 4 (Bedrock)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'anthropic.claude-opus-4-1-20250805-v1:0',
    name: 'Claude Opus 4.1 (Bedrock)',
    provider: 'bedrock',
    contextLength: 200000,
  },

  // Cohere Models
  {
    id: 'cohere.command-text-v14',
    name: 'Cohere Command Text v14 (Bedrock)',
    provider: 'bedrock',
    contextLength: 4000,
  },
  {
    id: 'cohere.command-light-text-v14',
    name: 'Cohere Command Light Text v14 (Bedrock)',
    provider: 'bedrock',
    contextLength: 4000,
  },
  {
    id: 'cohere.command-r-v1:0',
    name: 'Cohere Command R (Bedrock)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'cohere.command-r-plus-v1:0',
    name: 'Cohere Command R Plus (Bedrock)',
    provider: 'bedrock',
    contextLength: 128000,
  },

  // Meta Llama Models
  {
    id: 'meta.llama3-8b-instruct-v1:0',
    name: 'Llama 3 8B (Bedrock)',
    provider: 'bedrock',
    contextLength: 8000,
  },
  {
    id: 'meta.llama3-70b-instruct-v1:0',
    name: 'Llama 3 70B (Bedrock)',
    provider: 'bedrock',
    contextLength: 8000,
  },
  {
    id: 'meta.llama3-1-8b-instruct-v1:0',
    name: 'Llama 3.1 8B (Bedrock)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'meta.llama3-1-70b-instruct-v1:0',
    name: 'Llama 3.1 70B (Bedrock)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'meta.llama3-1-405b-instruct-v1:0',
    name: 'Llama 3.1 405B (Bedrock)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'meta.llama3-2-1b-instruct-v1:0',
    name: 'Llama 3.2 1B (Bedrock)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'meta.llama3-2-3b-instruct-v1:0',
    name: 'Llama 3.2 3B (Bedrock)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'meta.llama3-2-11b-instruct-v1:0',
    name: 'Llama 3.2 11B (Bedrock)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'meta.llama3-2-90b-instruct-v1:0',
    name: 'Llama 3.2 90B (Bedrock)',
    provider: 'bedrock',
    contextLength: 128000,
  },

  // Mistral Models
  {
    id: 'mistral.mistral-7b-instruct-v0:2',
    name: 'Mistral 7B Instruct (Bedrock)',
    provider: 'bedrock',
    contextLength: 32000,
  },
  {
    id: 'mistral.mixtral-8x7b-instruct-v0:1',
    name: 'Mistral Mixtral 8x7B (Bedrock)',
    provider: 'bedrock',
    contextLength: 32000,
  },
  {
    id: 'mistral.mistral-small-2402-v1:0',
    name: 'Mistral Small (Bedrock)',
    provider: 'bedrock',
    contextLength: 32000,
  },
  {
    id: 'mistral.mistral-large-2402-v1:0',
    name: 'Mistral Large (Bedrock)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'mistral.mistral-large-2407-v1:0',
    name: 'Mistral Large 2407 (Bedrock)',
    provider: 'bedrock',
    contextLength: 128000,
  },

  // OpenAI Models on Bedrock
  {
    id: 'openai.gpt-oss-20b-1:0',
    name: 'GPT OSS 20B (Bedrock)',
    provider: 'bedrock',
    contextLength: 8000,
  },
  {
    id: 'openai.gpt-oss-120b-1:0',
    name: 'GPT OSS 120B (Bedrock)',
    provider: 'bedrock',
    contextLength: 8000,
  },

  // US Region - Amazon Nova Models
  {
    id: 'us.amazon.nova-micro-v1:0',
    name: 'Amazon Nova Micro (US)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.amazon.nova-lite-v1:0',
    name: 'Amazon Nova Lite (US)',
    provider: 'bedrock',
    contextLength: 300000,
  },
  {
    id: 'us.amazon.nova-pro-v1:0',
    name: 'Amazon Nova Pro (US)',
    provider: 'bedrock',
    contextLength: 300000,
  },
  {
    id: 'us.amazon.nova-premier-v1:0',
    name: 'Amazon Nova Premier (US)',
    provider: 'bedrock',
    contextLength: 300000,
  },

  // US Region - Anthropic Claude Models
  {
    id: 'us.anthropic.claude-3-haiku-20240307-v1:0',
    name: 'Claude 3 Haiku (US)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-3-sonnet-20240229-v1:0',
    name: 'Claude 3 Sonnet (US)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-3-opus-20240229-v1:0',
    name: 'Claude 3 Opus (US)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-3-5-haiku-20241022-v1:0',
    name: 'Claude 3.5 Haiku (US)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-3-5-sonnet-20240620-v1:0',
    name: 'Claude 3.5 Sonnet (US)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-3-5-sonnet-20241022-v2:0',
    name: 'Claude 3.5 Sonnet v2 (US)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-3-7-sonnet-20250219-v1:0',
    name: 'Claude 3.7 Sonnet (US)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-sonnet-4-20250514-v1:0',
    name: 'Claude Sonnet 4 (US)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-sonnet-4-5-20250929-v1:0',
    name: 'Claude Sonnet 4.5 (US)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-opus-4-20250514-v1:0',
    name: 'Claude Opus 4 (US)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'us.anthropic.claude-opus-4-1-20250805-v1:0',
    name: 'Claude Opus 4.1 (US)',
    provider: 'bedrock',
    contextLength: 200000,
  },

  // US Region - Meta Llama Models
  {
    id: 'us.meta.llama3-1-8b-instruct-v1:0',
    name: 'Llama 3.1 8B (US)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama3-1-70b-instruct-v1:0',
    name: 'Llama 3.1 70B (US)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama3-2-1b-instruct-v1:0',
    name: 'Llama 3.2 1B (US)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama3-2-3b-instruct-v1:0',
    name: 'Llama 3.2 3B (US)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama3-2-11b-instruct-v1:0',
    name: 'Llama 3.2 11B (US)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama3-2-90b-instruct-v1:0',
    name: 'Llama 3.2 90B (US)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama3-3-70b-instruct-v1:0',
    name: 'Llama 3.3 70B (US)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama4-scout-17b-instruct-v1:0',
    name: 'Llama 4 Scout 17B (US)',
    provider: 'bedrock',
    contextLength: 128000,
  },
  {
    id: 'us.meta.llama4-maverick-17b-instruct-v1:0',
    name: 'Llama 4 Maverick 17B (US)',
    provider: 'bedrock',
    contextLength: 128000,
  },

  // US Region - Mistral Models
  {
    id: 'us.mistral.pixtral-large-2502-v1:0',
    name: 'Mistral Pixtral Large (US)',
    provider: 'bedrock',
    contextLength: 128000,
  },

  // US Region - DeepSeek Models
  {
    id: 'us.deepseek.r1-v1:0',
    name: 'DeepSeek R1 (US)',
    provider: 'bedrock',
    contextLength: 64000,
  },

  // Global Region - Anthropic Claude Models
  {
    id: 'global.anthropic.claude-haiku-4-5-20251001-v1:0',
    name: 'Claude Haiku 4.5 (Global)',
    provider: 'bedrock',
    contextLength: 200000,
  },
  {
    id: 'global.anthropic.claude-sonnet-4-5-20250929-v1:0',
    name: 'Claude Sonnet 4.5 (Global)',
    provider: 'bedrock',
    contextLength: 200000,
  },
];
