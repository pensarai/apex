import type { ModelInfo } from "../ai";

export const PENSAR_MODELS: ModelInfo[] = [
  {
    // GPT 5.5 via Bedrock Mantle, routed through the Pensar Gateway for
    // usage-based billing. The gateway proxies to the OpenAI Responses API.
    id: "pensar:openai.gpt-5.5",
    name: "GPT 5.5 (Pensar)",
    provider: "pensar",
    contextLength: 272000,
  },
  {
    id: "pensar:anthropic.claude-opus-4-8",
    name: "Claude Opus 4.8",
    provider: "pensar",
    contextLength: 1000000,
  },
  {
    id: "pensar:anthropic.claude-opus-4-7",
    name: "Claude Opus 4.7",
    provider: "pensar",
    contextLength: 1000000,
  },
  {
    id: "pensar:anthropic.claude-opus-4-6-v1",
    name: "Claude Opus 4.6",
    provider: "pensar",
    contextLength: 1000000,
  },
  {
    id: "pensar:anthropic.claude-sonnet-4-5-20250929-v1:0",
    name: "Claude Sonnet 4.5",
    provider: "pensar",
    contextLength: 200000,
  },
  {
    id: "pensar:anthropic.claude-haiku-4-5-20251001-v1:0",
    name: "Claude Haiku 4.5",
    provider: "pensar",
    contextLength: 200000,
  },
  {
    id: "pensar:anthropic.claude-sonnet-4-20250514-v1:0",
    name: "Claude Sonnet 4",
    provider: "pensar",
    contextLength: 200000,
  },
  {
    id: "pensar:anthropic.claude-opus-4-20250514-v1:0",
    name: "Claude Opus 4",
    provider: "pensar",
    contextLength: 200000,
  },
  {
    id: "pensar:anthropic.claude-3-7-sonnet-20250219-v1:0",
    name: "Claude 3.7 Sonnet",
    provider: "pensar",
    contextLength: 200000,
  },
  {
    id: "pensar:anthropic.claude-3-5-haiku-20241022-v1:0",
    name: "Claude 3.5 Haiku",
    provider: "pensar",
    contextLength: 200000,
  },
];
