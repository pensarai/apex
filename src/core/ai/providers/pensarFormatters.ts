import type {
  LanguageModelV3CallOptions,
  LanguageModelV3Content,
  LanguageModelV3FinishReason,
  LanguageModelV3TextPart,
  LanguageModelV3ToolCallPart,
  LanguageModelV3ToolResultPart,
} from "@ai-sdk/provider";

export function convertToBedrockFormat(
  modelId: string,
  options: LanguageModelV3CallOptions,
): Record<string, unknown> {
  if (modelId.includes("anthropic.claude")) {
    return convertToAnthropicFormat(modelId, options);
  }

  // Fallback: attempt Anthropic format for unknown models
  return convertToAnthropicFormat(modelId, options);
}

function getDefaultMaxOutputTokens(modelId: string): number {
  if (
    modelId.includes("claude-opus-4-6") ||
    modelId.includes("claude-sonnet-4-6")
  ) {
    return 128_000;
  }
  if (
    modelId.includes("claude-sonnet-4-5") ||
    modelId.includes("claude-opus-4-5") ||
    modelId.includes("claude-haiku-4-5")
  ) {
    return 64_000;
  }
  if (modelId.includes("claude-opus-4-1")) {
    return 32_000;
  }
  if (
    modelId.includes("claude-sonnet-4-") ||
    modelId.includes("claude-3-7-sonnet")
  ) {
    return 64_000;
  }
  if (modelId.includes("claude-opus-4-")) {
    return 32_000;
  }
  if (modelId.includes("claude-3-5-haiku")) {
    return 8_192;
  }
  return 4_096;
}

const EPHEMERAL_CACHE_CONTROL = { type: "ephemeral" as const };

function hasCacheControl(part: Record<string, unknown>): boolean {
  const opts = part.providerOptions as
    | Record<string, Record<string, unknown>>
    | undefined;
  return !!opts?.anthropic?.cacheControl;
}

function convertToAnthropicFormat(
  modelId: string,
  options: LanguageModelV3CallOptions,
): Record<string, unknown> {
  const messages: Array<{
    role: string;
    content: string | Array<Record<string, unknown>>;
  }> = [];
  let systemPrompt: string | undefined;
  let systemHasCacheControl = false;

  // Extract system prompt and convert messages from V2 prompt format
  if (options.prompt) {
    for (const part of options.prompt) {
      if (part.role === "system") {
        systemPrompt = part.content;
        systemHasCacheControl = hasCacheControl(
          part as unknown as Record<string, unknown>,
        );
      } else if (part.role === "user") {
        const partHasCache = hasCacheControl(
          part as unknown as Record<string, unknown>,
        );
        const text = (part.content as Array<LanguageModelV3TextPart>)
          .map((c: LanguageModelV3TextPart) => {
            if (c.type === "text") return c.text;
            if (c.type === "file") return "[file]";
            return "";
          })
          .join("");
        if (partHasCache) {
          messages.push({
            role: "user",
            content: [
              { type: "text", text, cache_control: EPHEMERAL_CACHE_CONTROL },
            ],
          });
        } else {
          messages.push({ role: "user", content: text });
        }
      } else if (part.role === "assistant") {
        const assistantContent = part.content as Array<
          LanguageModelV3TextPart | LanguageModelV3ToolCallPart
        >;
        const hasToolCalls = assistantContent.some(
          (c) => c.type === "tool-call",
        );

        if (hasToolCalls) {
          // Must use structured content array so Bedrock sees tool_use blocks
          const content: Array<Record<string, unknown>> = [];
          for (const c of assistantContent) {
            if (c.type === "text" && c.text) {
              content.push({ type: "text", text: c.text });
            } else if (c.type === "tool-call") {
              const parsedInput =
                typeof c.input === "string" ? JSON.parse(c.input) : c.input;
              content.push({
                type: "tool_use",
                id: c.toolCallId,
                name: c.toolName,
                input: parsedInput,
              });
            }
          }
          messages.push({ role: "assistant", content });
        } else {
          // Text-only assistant messages can use a plain string
          const text = assistantContent
            .map((c) => (c.type === "text" ? c.text : ""))
            .join("");
          messages.push({ role: "assistant", content: text });
        }
      } else if (part.role === "tool") {
        // Tool results get appended as user messages in Anthropic format
        const toolResults = (
          part.content as Array<LanguageModelV3ToolResultPart>
        ).map((c: LanguageModelV3ToolResultPart) => {
          let resultContent: string;
          if (c.output.type === "text") {
            resultContent = c.output.value;
          } else if (c.output.type === "json") {
            resultContent = JSON.stringify(c.output.value);
          } else if (c.output.type === "execution-denied") {
            resultContent = c.output.reason ?? "Tool execution denied";
          } else {
            resultContent = JSON.stringify(c.output);
          }
          return {
            type: "tool_result",
            tool_use_id: c.toolCallId,
            content: resultContent,
          };
        });
        messages.push({ role: "user", content: toolResults });
      }
    }
  }

  // Handle responseFormat — Anthropic/Bedrock has no native JSON mode,
  // so we inject instructions into the system prompt.
  if (options.responseFormat?.type === "json") {
    const jsonInstruction = options.responseFormat.schema
      ? `\n\nYou MUST respond with ONLY valid JSON matching this schema (no markdown, no explanation, no code fences):\n${JSON.stringify(options.responseFormat.schema)}`
      : `\n\nYou MUST respond with ONLY valid JSON (no markdown, no explanation, no code fences).`;
    systemPrompt = (systemPrompt || "") + jsonInstruction;
  }

  // Build request body
  const body: Record<string, unknown> = {
    anthropic_version: "bedrock-2023-05-31",
    messages,
    max_tokens: options.maxOutputTokens ?? getDefaultMaxOutputTokens(modelId),
  };

  if (systemPrompt) {
    body.system = systemHasCacheControl
      ? [
          {
            type: "text",
            text: systemPrompt,
            cache_control: EPHEMERAL_CACHE_CONTROL,
          },
        ]
      : systemPrompt;
  }

  if (options.temperature != null) {
    body.temperature = options.temperature;
  }

  if (options.topP != null) {
    body.top_p = options.topP;
  }

  if (options.stopSequences && options.stopSequences.length > 0) {
    body.stop_sequences = options.stopSequences;
  }

  // Convert tools
  if (options.tools && options.tools.length > 0) {
    body.tools = options.tools
      .filter(
        (tool): tool is Extract<typeof tool, { type: "function" }> =>
          tool.type === "function",
      )
      .map((tool) => ({
        name: tool.name,
        description: tool.description,
        input_schema: tool.inputSchema,
      }));
  }

  // Convert tool choice
  if (options.toolChoice) {
    if (options.toolChoice.type === "auto") {
      body.tool_choice = { type: "auto" };
    } else if (options.toolChoice.type === "required") {
      body.tool_choice = { type: "any" };
    } else if (options.toolChoice.type === "none") {
      // Strip tools entirely so the model cannot call any
      delete body.tools;
    } else if (options.toolChoice.type === "tool") {
      body.tool_choice = {
        type: "tool",
        name: options.toolChoice.toolName,
      };
    }
  }

  return body;
}

export function parseBedrockResponse(
  modelId: string,
  response: Record<string, unknown>,
  usage: { inputTokens: number; outputTokens: number },
): {
  content: LanguageModelV3Content[];
  finishReason: LanguageModelV3FinishReason;
  usage: {
    inputTokens: {
      total: number | undefined;
      noCache: undefined;
      cacheRead: undefined;
      cacheWrite: undefined;
    };
    outputTokens: {
      total: number | undefined;
      text: undefined;
      reasoning: undefined;
    };
  };
} {
  if (modelId.includes("anthropic.claude")) {
    return parseAnthropicResponse(response, usage);
  }

  return parseAnthropicResponse(response, usage);
}

function parseAnthropicResponse(
  response: Record<string, unknown>,
  usage: { inputTokens: number; outputTokens: number },
): {
  content: LanguageModelV3Content[];
  finishReason: LanguageModelV3FinishReason;
  usage: {
    inputTokens: {
      total: number | undefined;
      noCache: undefined;
      cacheRead: undefined;
      cacheWrite: undefined;
    };
    outputTokens: {
      total: number | undefined;
      text: undefined;
      reasoning: undefined;
    };
  };
} {
  const rawContent = response.content as
    | Array<Record<string, unknown>>
    | undefined;
  const content: LanguageModelV3Content[] = [];

  if (rawContent) {
    for (const block of rawContent) {
      if (block.type === "text") {
        content.push({
          type: "text",
          text: block.text as string,
        });
      } else if (block.type === "tool_use") {
        content.push({
          type: "tool-call",
          toolCallId: block.id as string,
          toolName: block.name as string,
          input:
            typeof block.input === "string"
              ? block.input
              : JSON.stringify(block.input),
        });
      }
    }
  }

  const stopReason = response.stop_reason as string | undefined;
  const finishReason: LanguageModelV3FinishReason = {
    unified: mapStopReasonV3(stopReason),
    raw: stopReason,
  };

  const respUsage = response.usage as
    | { input_tokens?: number; output_tokens?: number }
    | undefined;
  const finalUsage = {
    inputTokens: {
      total: respUsage?.input_tokens ?? usage.inputTokens,
      noCache: undefined as undefined,
      cacheRead: undefined as undefined,
      cacheWrite: undefined as undefined,
    },
    outputTokens: {
      total: respUsage?.output_tokens ?? usage.outputTokens,
      text: undefined as undefined,
      reasoning: undefined as undefined,
    },
  };

  return { content, finishReason, usage: finalUsage };
}

function mapStopReasonV3(
  reason: string | undefined,
): LanguageModelV3FinishReason["unified"] {
  switch (reason) {
    case "end_turn":
    case "stop_sequence":
      return "stop";
    case "max_tokens":
      return "length";
    case "tool_use":
      return "tool-calls";
    default:
      return "other";
  }
}
