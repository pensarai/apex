import type {
  LanguageModelV3CallOptions,
  LanguageModelV3Content,
  LanguageModelV3FinishReason,
  LanguageModelV3TextPart,
  LanguageModelV3ToolResultPart,
} from "@ai-sdk/provider";
import { isMantleResponsesModelId } from "../mantle";
import { getMaxOutputTokens } from "../models";

export function convertToBedrockFormat(
  modelId: string,
  options: LanguageModelV3CallOptions,
): Record<string, unknown> {
  // GPT-5.x on Bedrock Mantle speaks the OpenAI Responses API, which has a
  // different request shape than Anthropic Messages.
  if (isMantleResponsesModelId(modelId)) {
    return convertToResponsesFormat(modelId, options);
  }

  if (modelId.includes("anthropic.claude")) {
    return convertToAnthropicFormat(modelId, options);
  }

  // Fallback: attempt Anthropic format for unknown models
  return convertToAnthropicFormat(modelId, options);
}

/**
 * Convert AI-SDK call options to an OpenAI Responses API request body for
 * Bedrock Mantle (`POST …/openai/v1/responses`). System prompt → `instructions`;
 * messages → typed `input` items; tool calls/results → `function_call` /
 * `function_call_output` items. Temperature/top_p are omitted because GPT-5.x
 * are reasoning models that reject sampling params on the Responses API.
 */
function convertToResponsesFormat(
  modelId: string,
  options: LanguageModelV3CallOptions,
): Record<string, unknown> {
  const input: Array<Record<string, unknown>> = [];
  let instructions: string | undefined;

  if (options.prompt) {
    for (const part of options.prompt) {
      if (part.role === "system") {
        instructions = instructions
          ? `${instructions}\n\n${part.content}`
          : part.content;
      } else if (part.role === "user") {
        const text = (part.content as Array<LanguageModelV3TextPart>)
          .map((c: LanguageModelV3TextPart) => {
            if (c.type === "text") return c.text;
            if (c.type === "file") return "[file]";
            return "";
          })
          .join("");
        input.push({
          role: "user",
          content: [{ type: "input_text", text }],
        });
      } else if (part.role === "assistant") {
        const assistantContent = part.content as unknown as Array<
          Record<string, unknown>
        >;
        const text = assistantContent
          .filter((c) => c.type === "text")
          .map((c) => c.text as string)
          .join("");
        if (text) {
          input.push({
            role: "assistant",
            content: [{ type: "output_text", text }],
          });
        }
        for (const c of assistantContent) {
          if (c.type === "tool-call") {
            input.push({
              type: "function_call",
              call_id: c.toolCallId,
              name: c.toolName,
              arguments:
                typeof c.input === "string"
                  ? c.input
                  : JSON.stringify(c.input ?? {}),
            });
          }
          // Reasoning parts are server-managed on the Responses API and are
          // not replayed back as input.
        }
      } else if (part.role === "tool") {
        for (const c of part.content as Array<LanguageModelV3ToolResultPart>) {
          let outputText: string;
          if (c.output.type === "text") {
            outputText = c.output.value;
          } else if (c.output.type === "json") {
            outputText = JSON.stringify(c.output.value);
          } else if (c.output.type === "execution-denied") {
            outputText = c.output.reason ?? "Tool execution denied";
          } else {
            outputText = JSON.stringify(c.output);
          }
          input.push({
            type: "function_call_output",
            call_id: c.toolCallId,
            output: outputText,
          });
        }
      }
    }
  }

  const body: Record<string, unknown> = {
    input,
    max_output_tokens: options.maxOutputTokens ?? getMaxOutputTokens(modelId),
    stream: true,
  };

  if (instructions) {
    body.instructions = instructions;
  }

  if (options.responseFormat?.type === "json") {
    body.text = options.responseFormat.schema
      ? {
          format: {
            type: "json_schema",
            name: "response",
            schema: options.responseFormat.schema,
          },
        }
      : { format: { type: "json_object" } };
  }

  if (options.tools && options.tools.length > 0) {
    body.tools = options.tools
      .filter(
        (tool): tool is Extract<typeof tool, { type: "function" }> =>
          tool.type === "function",
      )
      .map((tool) => ({
        type: "function",
        name: tool.name,
        description: tool.description,
        parameters: tool.inputSchema,
      }));
  }

  if (options.toolChoice) {
    if (options.toolChoice.type === "auto") {
      body.tool_choice = "auto";
    } else if (options.toolChoice.type === "required") {
      body.tool_choice = "required";
    } else if (options.toolChoice.type === "none") {
      delete body.tools;
    } else if (options.toolChoice.type === "tool") {
      body.tool_choice = {
        type: "function",
        name: options.toolChoice.toolName,
      };
    }
  }

  return body;
}

const EPHEMERAL_CACHE_CONTROL = { type: "ephemeral" as const };

function hasCacheControl(part: Record<string, unknown>): boolean {
  const opts = part.providerOptions as
    | Record<string, Record<string, unknown>>
    | undefined;
  return !!opts?.anthropic?.cacheControl;
}

/**
 * Anthropic carries the breakpoint on a content block, so mirror the part's
 * cache_control onto the last block emitted for it. Without this the
 * incremental breakpoint `withCachedLastMessage` sets is dropped on every
 * assistant and tool-result turn — i.e. most of an agent loop.
 */
function applyCacheControl(message: {
  role: string;
  content: string | Array<Record<string, unknown>>;
}): void {
  if (typeof message.content === "string") {
    // An empty text block is rejected outright; leave it alone.
    if (message.content === "") return;
    message.content = [
      {
        type: "text",
        text: message.content,
        cache_control: EPHEMERAL_CACHE_CONTROL,
      },
    ];
    return;
  }
  const last = message.content[message.content.length - 1];
  // cache_control is not accepted on thinking blocks.
  if (!last || last.type === "thinking") return;
  last.cache_control = EPHEMERAL_CACHE_CONTROL;
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
        const text = (part.content as Array<LanguageModelV3TextPart>)
          .map((c: LanguageModelV3TextPart) => {
            if (c.type === "text") return c.text;
            if (c.type === "file") return "[file]";
            return "";
          })
          .join("");
        messages.push({ role: "user", content: text });
      } else if (part.role === "assistant") {
        const assistantContent = part.content as unknown as Array<
          Record<string, unknown>
        >;
        const hasStructuredParts = assistantContent.some(
          (c) => c.type === "tool-call" || c.type === "reasoning",
        );

        if (hasStructuredParts) {
          // Must use structured content array for tool_use / thinking blocks
          const content: Array<Record<string, unknown>> = [];
          for (const c of assistantContent) {
            if (c.type === "reasoning") {
              const sig = (
                c.providerOptions as
                  | Record<string, Record<string, unknown>>
                  | undefined
              )?.anthropic?.signature as string | undefined;
              const thinkingBlock: Record<string, unknown> = {
                type: "thinking",
                thinking: c.text as string,
              };
              if (sig) thinkingBlock.signature = sig;
              content.push(thinkingBlock);
            } else if (c.type === "text" && c.text) {
              content.push({ type: "text", text: c.text as string });
            } else if (c.type === "tool-call") {
              const parsedInput =
                typeof c.input === "string"
                  ? JSON.parse(c.input as string)
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
            .map((c) => (c.type === "text" ? (c.text as string) : ""))
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

      const pushed = messages[messages.length - 1];
      if (
        part.role !== "system" &&
        pushed &&
        hasCacheControl(part as unknown as Record<string, unknown>)
      ) {
        applyCacheControl(pushed);
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
    max_tokens: options.maxOutputTokens ?? getMaxOutputTokens(modelId),
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

  // Extended thinking
  const anthropicOpts = options.providerOptions?.anthropic as
    | Record<string, unknown>
    | undefined;
  const thinking = anthropicOpts?.thinking as
    | { type: string; budgetTokens?: number }
    | undefined;
  if (thinking?.type === "enabled") {
    const budgetTokens = thinking.budgetTokens ?? 10_000;
    body.thinking = { type: "enabled", budget_tokens: budgetTokens };
    // Anthropic requires max_tokens > budget_tokens
    if ((body.max_tokens as number) <= budgetTokens) {
      body.max_tokens = budgetTokens + 4096;
    }
    // Anthropic rejects temperature when thinking is enabled
    delete body.temperature;
  } else if (thinking?.type === "adaptive") {
    body.thinking = { type: "adaptive" };
    delete body.temperature;
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

function parseBedrockResponse(
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
      if (block.type === "thinking") {
        const reasoningPart: Record<string, unknown> = {
          type: "reasoning",
          text: block.thinking as string,
        };
        if (block.signature) {
          reasoningPart.providerMetadata = {
            anthropic: { signature: block.signature as string },
          };
        }
        content.push(reasoningPart as LanguageModelV3Content);
      } else if (block.type === "text") {
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
