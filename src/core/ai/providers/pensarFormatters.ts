import type {
  LanguageModelV2CallOptions,
  LanguageModelV2Content,
  LanguageModelV2FinishReason,
  LanguageModelV2Message,
  LanguageModelV2TextPart,
  LanguageModelV2ToolCallPart,
  LanguageModelV2ToolResultPart,
} from "@ai-sdk/provider";

/**
 * Converts Vercel AI SDK LanguageModelV2CallOptions into a Bedrock-compatible
 * request body. Currently supports Anthropic Claude models (the primary models
 * available through Pensar). Other model families can be added incrementally.
 */
export function convertToBedrockFormat(
  modelId: string,
  options: LanguageModelV2CallOptions
): Record<string, unknown> {
  if (modelId.includes("anthropic.claude")) {
    return convertToAnthropicFormat(options);
  }

  // Fallback: attempt Anthropic format for unknown models
  return convertToAnthropicFormat(options);
}

function convertToAnthropicFormat(
  options: LanguageModelV2CallOptions
): Record<string, unknown> {
  const messages: Array<{
    role: string;
    content: string | Array<Record<string, unknown>>;
  }> = [];
  let systemPrompt: string | undefined;

  // Extract system prompt and convert messages from V2 prompt format
  if (options.prompt) {
    for (const part of options.prompt) {
      if (part.role === "system") {
        systemPrompt = part.content;
      } else if (part.role === "user") {
        const content = (part.content as Array<LanguageModelV2TextPart>)
          .map((c: LanguageModelV2TextPart) => {
            if (c.type === "text") return c.text;
            if (c.type === "file") return "[file]";
            return "";
          })
          .join("");
        messages.push({ role: "user", content });
      } else if (part.role === "assistant") {
        const assistantContent = part.content as Array<
          LanguageModelV2TextPart | LanguageModelV2ToolCallPart
        >;
        const hasToolCalls = assistantContent.some(
          (c) => c.type === "tool-call"
        );

        if (hasToolCalls) {
          // Must use structured content array so Bedrock sees tool_use blocks
          const content: Array<Record<string, unknown>> = [];
          for (const c of assistantContent) {
            if (c.type === "text" && c.text) {
              content.push({ type: "text", text: c.text });
            } else if (c.type === "tool-call") {
              const parsedInput =
                typeof c.input === "string"
                  ? JSON.parse(c.input)
                  : c.input;
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
          part.content as Array<LanguageModelV2ToolResultPart>
        ).map((c: LanguageModelV2ToolResultPart) => {
          // V2 uses `output` with typed objects instead of `result`
          let resultContent: string;
          if (c.output.type === "text" || c.output.type === "error-text") {
            resultContent = c.output.value;
          } else {
            resultContent = JSON.stringify(c.output.value);
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

  // Build request body
  const body: Record<string, unknown> = {
    anthropic_version: "bedrock-2023-05-31",
    messages,
    max_tokens: options.maxOutputTokens ?? 4096,
  };

  if (systemPrompt) {
    body.system = systemPrompt;
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
          tool.type === "function"
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
      // Omit tool_choice to let the model decide (no forced tool use)
    } else if (options.toolChoice.type === "tool") {
      body.tool_choice = {
        type: "tool",
        name: options.toolChoice.toolName,
      };
    }
  }

  return body;
}

/**
 * Parses a Bedrock Anthropic response into the V2 content array format
 * expected by LanguageModelV2.doGenerate().
 */
export function parseBedrockResponse(
  modelId: string,
  response: Record<string, unknown>,
  usage: { inputTokens: number; outputTokens: number }
): {
  content: LanguageModelV2Content[];
  finishReason: LanguageModelV2FinishReason;
  usage: { inputTokens: number | undefined; outputTokens: number | undefined; totalTokens: number | undefined };
} {
  if (modelId.includes("anthropic.claude")) {
    return parseAnthropicResponse(response, usage);
  }

  // Fallback: attempt Anthropic parsing
  return parseAnthropicResponse(response, usage);
}

function parseAnthropicResponse(
  response: Record<string, unknown>,
  usage: { inputTokens: number; outputTokens: number }
): {
  content: LanguageModelV2Content[];
  finishReason: LanguageModelV2FinishReason;
  usage: { inputTokens: number | undefined; outputTokens: number | undefined; totalTokens: number | undefined };
} {
  const rawContent = response.content as
    | Array<Record<string, unknown>>
    | undefined;
  const content: LanguageModelV2Content[] = [];

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

  // Map Anthropic stop_reason to AI SDK finish reason
  const stopReason = response.stop_reason as string | undefined;
  let finishReason: LanguageModelV2FinishReason = "unknown";
  switch (stopReason) {
    case "end_turn":
      finishReason = "stop";
      break;
    case "tool_use":
      finishReason = "tool-calls";
      break;
    case "max_tokens":
      finishReason = "length";
      break;
    case "stop_sequence":
      finishReason = "stop";
      break;
  }

  // Prefer response-level usage if available
  const respUsage = response.usage as
    | { input_tokens?: number; output_tokens?: number }
    | undefined;
  const finalUsage = {
    inputTokens: respUsage?.input_tokens ?? usage.inputTokens,
    outputTokens: respUsage?.output_tokens ?? usage.outputTokens,
    totalTokens:
      (respUsage?.input_tokens ?? usage.inputTokens) +
      (respUsage?.output_tokens ?? usage.outputTokens),
  };

  return { content, finishReason, usage: finalUsage };
}
