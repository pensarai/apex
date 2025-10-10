import { createAnthropic } from "@ai-sdk/anthropic";
import type { AnthropicMessagesModelId } from "@ai-sdk/anthropic/internal";
import {
  streamText,
  type ModelMessage,
  type StopCondition,
  type StreamTextOnStepFinishCallback,
  type ToolChoice,
  type ToolSet,
} from "ai";

export type AIModel = AnthropicMessagesModelId;

export type AIModelProvider = "anthropic" | "openai" | "openrouter" | "bedrock";

// Available models with names
export interface ModelInfo {
  id: AIModel;
  name: string;
  provider: AIModelProvider;
}

export const AVAILABLE_MODELS: ModelInfo[] = [
  { id: "claude-sonnet-4-5", name: "Claude Sonnet 4.5", provider: "anthropic" },
  {
    id: "claude-sonnet-4-5-20250929",
    name: "Claude Sonnet 4.5 (2025-09-29)",
    provider: "anthropic",
  },
  { id: "claude-opus-4-1", name: "Claude Opus 4.1", provider: "anthropic" },
  {
    id: "claude-opus-4-1-20250805",
    name: "Claude Opus 4.1 (2025-08-05)",
    provider: "anthropic",
  },
  { id: "claude-opus-4-0", name: "Claude Opus 4.0", provider: "anthropic" },
  {
    id: "claude-opus-4-20250514",
    name: "Claude Opus 4 (2025-05-14)",
    provider: "anthropic",
  },
  { id: "claude-sonnet-4-0", name: "Claude Sonnet 4.0", provider: "anthropic" },
  {
    id: "claude-sonnet-4-20250514",
    name: "Claude Sonnet 4 (2025-05-14)",
    provider: "anthropic",
  },
  {
    id: "claude-3-7-sonnet-latest",
    name: "Claude 3.7 Sonnet (Latest)",
    provider: "anthropic",
  },
  {
    id: "claude-3-7-sonnet-20250219",
    name: "Claude 3.7 Sonnet (2025-02-19)",
    provider: "anthropic",
  },
  {
    id: "claude-3-5-haiku-latest",
    name: "Claude 3.5 Haiku (Latest)",
    provider: "anthropic",
  },
  {
    id: "claude-3-5-haiku-20241022",
    name: "Claude 3.5 Haiku (2024-10-22)",
    provider: "anthropic",
  },
  {
    id: "claude-3-haiku-20240307",
    name: "Claude 3 Haiku (2024-03-07)",
    provider: "anthropic",
  },
];

export interface GetResponseProps {
  prompt: string;
  system?: string;
  model: AIModel;
  messages?: Array<ModelMessage>;
  stopWhen?:
    | StopCondition<NoInfer<ToolSet>>
    | StopCondition<NoInfer<ToolSet>>[];
  toolChoice?: ToolChoice<ToolSet>;
  tools?: ToolSet;
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
}

export function streamResponse(opts: GetResponseProps) {
  const {
    prompt,
    system,
    model,
    messages,
    stopWhen,
    toolChoice,
    tools,
    onStepFinish,
  } = opts;
  const anthropic = createAnthropic({
    apiKey: process.env.ANTHROPIC_API_KEY,
  });

  const response = streamText({
    model: anthropic(model),
    system,
    ...(messages ? { messages } : { prompt }),
    stopWhen,
    toolChoice,
    tools,
    onStepFinish,
  });

  return response;
}
