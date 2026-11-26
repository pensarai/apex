import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  applySequentialToolCallPolicy,
  buildOpenRouterProviderOptions,
  buildOpenRouterStructuredProviderOptions,
  buildReasoningProviderOptions,
  getOpenAIReasoningEfforts,
  isRepairFailClosedTool,
  modelSupportsOpenAIReasoning,
  normalizeOpenAIReasoningEffort,
  restrictToolsToActive,
  SEQUENTIAL_TOOL_CALL_INSTRUCTION,
  streamResponse,
  withResponseToolActive,
} from "./ai";
import { consumeStream } from "./utils";

// Skip tests if API keys are not available (e.g., in CI)
const hasApiKeys = process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY;
const describeOrSkip = hasApiKeys ? describe : describe.skip;

describe("applySequentialToolCallPolicy", () => {
  const tools = {
    probe: {
      description: "test tool",
      inputSchema: z.object({ q: z.string() }),
    },
  };

  it("appends the instruction for DeepSeek models when tools are bound", () => {
    const result = applySequentialToolCallPolicy(
      "Base system prompt.",
      tools,
      "deepseek.v3-v1:0",
    );
    expect(result).toBe(
      `Base system prompt.\n\n${SEQUENTIAL_TOOL_CALL_INSTRUCTION}`,
    );
  });

  it("uses the instruction alone when there is no base system prompt", () => {
    expect(
      applySequentialToolCallPolicy(undefined, tools, "deepseek.v3-v1:0"),
    ).toBe(SEQUENTIAL_TOOL_CALL_INSTRUCTION);
  });

  it("leaves the system prompt unchanged when no tools are bound", () => {
    expect(applySequentialToolCallPolicy("Base.", {}, "deepseek.v3-v1:0")).toBe(
      "Base.",
    );
    expect(
      applySequentialToolCallPolicy("Base.", undefined, "deepseek.v3-v1:0"),
    ).toBe("Base.");
  });

  it("leaves the system prompt unchanged for non-DeepSeek models", () => {
    expect(
      applySequentialToolCallPolicy("Base.", tools, "claude-haiku-4-5"),
    ).toBe("Base.");
  });
});

describe("restrictToolsToActive", () => {
  const tools = {
    read_file: {
      description: "read",
      inputSchema: z.object({ p: z.string() }),
    },
    execute_command: {
      description: "exec",
      inputSchema: z.object({ c: z.string() }),
    },
    delete_file: {
      description: "delete",
      inputSchema: z.object({ p: z.string() }),
    },
  };

  it("filters the tools map down to the activeTools allowlist", () => {
    const result = restrictToolsToActive(tools, ["read_file", "delete_file"]);
    expect(Object.keys(result ?? {}).sort()).toEqual([
      "delete_file",
      "read_file",
    ]);
    // execute_command must not be advertised, executable, or enumerable.
    expect(result).not.toHaveProperty("execute_command");
    // Retained tools keep their original definition (same reference).
    expect(result?.read_file).toBe(tools.read_file);
  });

  it("is a no-op when activeTools is empty (means: all tools)", () => {
    expect(restrictToolsToActive(tools, [])).toBe(tools);
  });

  it("is a no-op when activeTools is undefined", () => {
    expect(restrictToolsToActive(tools, undefined)).toBe(tools);
  });

  it("returns tools unchanged when tools is undefined", () => {
    expect(restrictToolsToActive(undefined, ["read_file"])).toBeUndefined();
  });

  it("ignores allowlist entries that are not present in the tools map", () => {
    const result = restrictToolsToActive(tools, ["read_file", "no_such_tool"]);
    expect(Object.keys(result ?? {})).toEqual(["read_file"]);
  });
});

describe("withResponseToolActive", () => {
  const tool = { description: "t", inputSchema: z.object({}) };
  const withResponse = { read_file: tool, response: tool };

  it("keeps an injected response tool reachable through a curated allowlist", () => {
    const allowed = withResponseToolActive(withResponse, ["read_file"]);
    expect(allowed).toEqual(["read_file", "response"]);
    expect(
      Object.keys(restrictToolsToActive(withResponse, allowed) ?? {}).sort(),
    ).toEqual(["read_file", "response"]);
  });

  it("does not add response when the caller did not inject it", () => {
    expect(withResponseToolActive({ read_file: tool }, ["read_file"])).toEqual([
      "read_file",
    ]);
  });

  it("leaves an allowlist that already names response untouched", () => {
    const active = ["response", "read_file"];
    expect(withResponseToolActive(withResponse, active)).toBe(active);
  });

  it("is a no-op when activeTools is empty or undefined", () => {
    expect(withResponseToolActive(withResponse, [])).toEqual([]);
    expect(withResponseToolActive(withResponse, undefined)).toBeUndefined();
  });
});

describe("isRepairFailClosedTool", () => {
  it("fails closed for spawn_pentest_agent so repair cannot fabricate a target", () => {
    expect(isRepairFailClosedTool("spawn_pentest_agent")).toBe(true);
  });

  it("leaves ordinary tools eligible for repair", () => {
    expect(isRepairFailClosedTool("response")).toBe(false);
    expect(isRepairFailClosedTool("http_request")).toBe(false);
  });

  it("keeps result-submission tools eligible for repair so a bad field is fixed, not dropped", () => {
    // These carry no authorization boundary; repair re-prompts the model to fix
    // a mis-shaped field instead of discarding a completed recon or finding.
    expect(isRepairFailClosedTool("submit_results")).toBe(false);
    expect(isRepairFailClosedTool("document_vulnerability")).toBe(false);
  });
});

describe("buildReasoningProviderOptions", () => {
  it("sends Claude Haiku 5.5 max effort through Bedrock", () => {
    expect(
      buildReasoningProviderOptions("global.anthropic.claude-haiku-5-5", {
        enableThinking: true,
        thinkingEffort: "max",
      }),
    ).toEqual({
      anthropic: {
        thinking: { type: "adaptive", display: "summarized" },
        effort: "max",
      },
      bedrock: {
        reasoningConfig: {
          type: "adaptive",
          display: "summarized",
          maxReasoningEffort: "max",
        },
      },
    });
  });

  it("uses Claude Haiku 5.5 medium effort by default and can disable thinking", () => {
    expect(
      buildReasoningProviderOptions("global.anthropic.claude-haiku-5-5", {
        enableThinking: true,
      }),
    ).toEqual({
      anthropic: {
        thinking: { type: "adaptive", display: "summarized" },
        effort: "medium",
      },
      bedrock: {
        reasoningConfig: {
          type: "adaptive",
          display: "summarized",
          maxReasoningEffort: "medium",
        },
      },
    });
    expect(
      buildReasoningProviderOptions("global.anthropic.claude-haiku-5-5", {
        enableThinking: false,
      }),
    ).toEqual({
      anthropic: { thinking: { type: "disabled" } },
      bedrock: {
        reasoningConfig: { type: "disabled" },
        additionalModelRequestFields: {
          thinking: { type: "disabled" },
        },
      },
    });
  });

  it("uses the documented budget mode for legacy Claude thinking", () => {
    for (const id of [
      "claude-sonnet-4-5",
      "claude-opus-4-20250514",
      "claude-opus-4-1-20250805",
      "claude-opus-4-5",
      "global.anthropic.claude-haiku-4-5-20251001-v1:0",
    ]) {
      expect(
        buildReasoningProviderOptions(id, { enableThinking: true }),
      ).toMatchObject({
        anthropic: { thinking: { type: "enabled", budgetTokens: 10000 } },
      });
    }
  });

  it("sends disabled thinking without an effort when the legacy toggle is off", () => {
    expect(
      buildReasoningProviderOptions("global.anthropic.claude-opus-4-6-v1", {
        enableThinking: false,
        thinkingEffort: "high",
      }),
    ).toMatchObject({
      anthropic: { thinking: { type: "disabled" } },
      bedrock: {
        additionalModelRequestFields: { thinking: { type: "disabled" } },
      },
    });
    expect(
      buildReasoningProviderOptions("global.anthropic.claude-opus-4-6-v1", {
        enableThinking: false,
      })?.anthropic?.effort,
    ).toBeUndefined();
  });

  it("returns undefined for a model that does not support thinking, even when enabled", () => {
    // claude-3-haiku has no extended thinking; the gate must not request it.
    expect(
      buildReasoningProviderOptions("claude-3-haiku-20240307", {
        enableThinking: true,
      }),
    ).toBeUndefined();
  });

  it("sets openai.reasoningEffort for an OpenAI reasoning model without thinking keys", () => {
    const result = buildReasoningProviderOptions("gpt-5.5", {
      openAIReasoningEffort: "high",
    });
    expect(result).toEqual({ openai: { reasoningEffort: "high" } });
    expect(result?.anthropic).toBeUndefined();
    expect(result?.bedrock).toBeUndefined();
  });

  it("sends GPT-5.6 ultra effort as the API-supported max value", () => {
    expect(
      buildReasoningProviderOptions("gpt-5.6-sol", {
        openAIReasoningEffort: "ultra",
      }),
    ).toEqual({ openai: { reasoningEffort: "max" } });
  });

  it("maps GLM 5.3 onto its always-on Concentrate effort levels", () => {
    const model = "concentrate:glm-5.3";

    expect(modelSupportsOpenAIReasoning(model)).toBe(true);
    expect(getOpenAIReasoningEfforts(model)).toEqual(["low", "high", "max"]);
    expect(normalizeOpenAIReasoningEffort(model, "none")).toBe("low");
    expect(normalizeOpenAIReasoningEffort(model, "medium")).toBe("high");
    expect(normalizeOpenAIReasoningEffort(model, "xhigh")).toBe("max");
    expect(normalizeOpenAIReasoningEffort(model)).toBe("high");
    expect(
      buildReasoningProviderOptions(model, {
        openAIReasoningEffort: "medium",
      }),
    ).toEqual({ openai: { reasoningEffort: "high" } });
  });

  it("carries adaptive effort through the native and Bedrock namespaces", () => {
    const result = buildReasoningProviderOptions(
      "global.anthropic.claude-opus-4-6-v1",
      { enableThinking: true, thinkingEffort: "low" },
    );
    expect(result?.anthropic).toEqual({
      thinking: { type: "adaptive", display: "summarized" },
      effort: "low",
    });
    expect(result?.bedrock).toEqual({
      reasoningConfig: {
        type: "adaptive",
        display: "summarized",
        maxReasoningEffort: "low",
      },
    });
  });

  it("selects the documented default when legacy thinking is enabled without effort", () => {
    expect(
      buildReasoningProviderOptions("global.anthropic.claude-opus-4-6-v1", {
        enableThinking: true,
      }),
    ).toMatchObject({
      anthropic: { effort: "high" },
      bedrock: { reasoningConfig: { maxReasoningEffort: "high" } },
    });
  });

  it("does not send an effort hint on a toggle-only model", () => {
    const result = buildReasoningProviderOptions(
      "global.anthropic.claude-haiku-4-5-20251001-v1:0",
      { enableThinking: true, thinkingEffort: "high" },
    );
    expect(result?.anthropic?.thinking).toEqual({
      type: "enabled",
      budgetTokens: 10000,
    });
    expect(result?.anthropic?.effort).toBeUndefined();
  });
});

describe("buildOpenRouterProviderOptions", () => {
  it("pins GLM 5.2 and 5.3 to Z.ai without provider fallbacks", () => {
    for (const model of ["z-ai/glm-5.2", "z-ai/glm-5.3"]) {
      expect(buildOpenRouterProviderOptions(model)).toEqual({
        openrouter: {
          provider: {
            only: ["z-ai"],
            allow_fallbacks: false,
          },
        },
      });
    }
  });

  it("asks for prompt caching on Anthropic models", () => {
    for (const model of [
      "anthropic/claude-haiku-5.5",
      "anthropic/claude-opus-5.5",
      "anthropic/claude-opus-4-6",
    ]) {
      expect(buildOpenRouterProviderOptions(model)).toEqual({
        openrouter: { cache_control: { type: "ephemeral" } },
      });
    }
  });

  it("leaves non-Anthropic, non-pinned OpenRouter models unchanged", () => {
    for (const model of ["openai/gpt-5.5-pro", "google/gemini-3-pro"]) {
      expect(buildOpenRouterProviderOptions(model)).toBe(undefined);
    }
  });

  it("does not ask for caching on Bedrock or native Anthropic ids", () => {
    for (const model of [
      "anthropic.claude-opus-4-6-v1",
      "global.anthropic.claude-haiku-4-5-20251001-v1:0",
      "claude-haiku-4-5",
    ]) {
      expect(buildOpenRouterProviderOptions(model)).toBe(undefined);
    }
  });
});

describe("buildOpenRouterStructuredProviderOptions", () => {
  it("prefers Z.ai but requires an endpoint that enforces the schema", () => {
    for (const model of ["z-ai/glm-5.2", "z-ai/glm-5.3"]) {
      expect(buildOpenRouterStructuredProviderOptions(model)).toEqual({
        openrouter: {
          provider: {
            order: ["z-ai"],
            allow_fallbacks: true,
            require_parameters: true,
          },
        },
      });
    }
  });

  it("asks for prompt caching on Anthropic models", () => {
    expect(
      buildOpenRouterStructuredProviderOptions("anthropic/claude-opus-4-6"),
    ).toEqual({ openrouter: { cache_control: { type: "ephemeral" } } });
  });

  it("leaves non-Anthropic, non-pinned OpenRouter models unchanged", () => {
    expect(buildOpenRouterStructuredProviderOptions("openai/gpt-5.5-pro")).toBe(
      undefined,
    );
  });
});

describeOrSkip("AI Stream Response", () => {
  it("should stream a basic response", async () => {
    console.log("\n=== Testing Basic Stream Response ===\n");

    const stream = streamResponse({
      model: "claude-haiku-4-5",
      system: "You are a helpful assistant.",
      prompt: "Say hello and explain what you can do in one sentence.",
    });

    let fullText = "";
    let toolCallCount = 0;
    let toolResultCount = 0;

    await consumeStream(stream, {
      onTextDelta: (delta) => {
        process.stdout.write(delta.text);
        fullText += delta.text;
      },
      onToolCall: (toolCall) => {
        toolCallCount++;
        console.log("\n[Tool Call]", toolCall.toolName, toolCall.input);
      },
      onToolResult: (toolResult) => {
        toolResultCount++;
        console.log("[Tool Result]", toolResult.toolName);
      },
    });

    console.log("\n\n--- Full Response ---");
    console.log(fullText);
    console.log("\n--- Stats ---");
    console.log(`Text length: ${fullText.length}`);
    console.log(`Tool calls: ${toolCallCount}`);
    console.log(`Tool results: ${toolResultCount}`);

    expect(fullText.length).toBeGreaterThan(0);
  });

  // it("should handle context length exceeded with summarization", async () => {
  //   console.log("\n=== Testing Context Length Handling ===\n");

  //   // Read the exhaust_context.txt file
  //   const exhaustContextPath = join(process.cwd(), "exhaust_context.txt");
  //   const exhaustContent = readFileSync(exhaustContextPath, "utf-8");

  //   console.log(`Loaded content: ${exhaustContent.length} characters`);
  //   console.log(
  //     "Attempting to send to API (should trigger context length error)...\n",
  //   );

  //   const stream = streamResponse({
  //     model: "claude-3-haiku-20240307", // Using a model with smaller context
  //     system: "You are a helpful assistant that analyzes text.",
  //     prompt: `Please analyze this text and give a very brief summary:\n\n${exhaustContent}\n\nWhat is this about?`,
  //   });

  //   let fullText = "";
  //   let toolCallCount = 0;
  //   let toolResultCount = 0;
  //   let sawSummarization = false;

  //   await consumeStream(stream, {
  //     onTextDelta: (delta) => {
  //       process.stdout.write(delta.text);
  //       fullText += delta.text;
  //     },
  //     onToolCall: (toolCall) => {
  //       toolCallCount++;
  //       console.log("\n\n[Tool Call]", toolCall.toolName);
  //       console.log("Input:", toolCall.input);

  //       if (toolCall.toolName === "summarize_conversation") {
  //         sawSummarization = true;
  //         console.log(
  //           "\n✓ Context length exceeded - automatic summarization triggered!",
  //         );
  //       }
  //     },
  //     onToolResult: (toolResult) => {
  //       toolResultCount++;
  //       console.log("\n[Tool Result]", toolResult.toolName);
  //     },
  //   });

  //   console.log("\n\n--- Full Response ---");
  //   console.log(fullText);
  //   console.log("\n--- Stats ---");
  //   console.log(`Text length: ${fullText.length}`);
  //   console.log(`Tool calls: ${toolCallCount}`);
  //   console.log(`Tool results: ${toolResultCount}`);
  //   console.log(`Saw summarization: ${sawSummarization}`);

  //   // Verify we got a response
  //   expect(fullText.length).toBeGreaterThan(0);

  //   // Verify summarization was triggered
  //   expect(sawSummarization).toBe(true);
  //   expect(toolCallCount).toBeGreaterThanOrEqual(1);
  //   expect(toolResultCount).toBeGreaterThanOrEqual(1);
  // });

  // it("should handle recursive context length errors (multiple summarizations)", async () => {
  //   console.log("\n=== Testing Recursive Context Length Handling ===\n");

  //   // This test verifies that if the summarization itself hits context limits,
  //   // it will recursively summarize again until it fits
  //   const exhaustContextPath = join(process.cwd(), "exhaust_context.txt");
  //   const exhaustContent = readFileSync(exhaustContextPath, "utf-8");

  //   console.log(`Loaded content: ${exhaustContent.length} characters`);
  //   console.log("Testing recursive summarization (may take a while)...\n");

  //   const stream = streamResponse({
  //     model: "claude-3-haiku-20240307",
  //     system: "You are a helpful assistant that provides concise summaries.",
  //     // Use the full content to trigger initial error
  //     prompt: `${exhaustContent}\n\nPlease provide a very brief summary of this content.`,
  //   });

  //   let fullText = "";
  //   let summarizationCount = 0;

  //   await consumeStream(stream, {
  //     onTextDelta: (delta) => {
  //       process.stdout.write(delta.text);
  //       fullText += delta.text;
  //     },
  //     onToolCall: (toolCall) => {
  //       if (toolCall.toolName === "summarize_conversation") {
  //         summarizationCount++;
  //         console.log(`\n\n[Summarization #${summarizationCount}]`);
  //         const input = JSON.parse(toolCall.input as string);
  //         console.log(`Reason: ${input.reason}`);
  //       }
  //     },
  //     onToolResult: (toolResult) => {
  //       if (toolResult.toolName === "summarize_conversation") {
  //         console.log("✓ Summarization completed");
  //       }
  //     },
  //   });

  //   console.log("\n\n--- Full Response ---");
  //   console.log(fullText);
  //   console.log(`\n--- Total summarizations: ${summarizationCount} ---`);

  //   // Verify we got a response and at least one summarization occurred
  //   expect(fullText.length).toBeGreaterThan(0);
  //   expect(summarizationCount).toBeGreaterThanOrEqual(1);

  //   console.log(
  //     `\n✅ Test passed! System handled ${summarizationCount} level(s) of recursive summarization`,
  //   );
  // });

  it.skip("should handle context length with message history", async () => {
    console.log("\n=== Testing Context Length with Message History ===\n");

    // Create a very long conversation history
    const messages = Array.from({ length: 100 }, (_, i) => ({
      role: (i % 2 === 0 ? "user" : "assistant") as "user" | "assistant",
      content: `This is message ${i + 1}. `.repeat(100), // Long messages
    }));

    console.log(`Created ${messages.length} messages in history`);
    console.log(
      "Attempting to send to API (should trigger context length error)...\n",
    );

    const stream = streamResponse({
      model: "gpt-3.5-turbo", // Smaller context window
      system: "You are a helpful assistant.",
      prompt: "Summarize our conversation so far.",
      messages,
    });

    let fullText = "";
    let sawSummarization = false;

    await consumeStream(stream, {
      onTextDelta: (delta) => {
        process.stdout.write(delta.text);
        fullText += delta.text;
      },
      onToolCall: (toolCall) => {
        console.log("\n\n[Tool Call]", toolCall.toolName);
        if (toolCall.toolName === "summarize_conversation") {
          sawSummarization = true;
          const input = JSON.parse(toolCall.input as string);
          console.log(`\n✓ Summarizing ${input.messageCount} messages`);
        }
      },
      onToolResult: (toolResult) => {
        console.log("\n[Tool Result]", toolResult.toolName);
      },
    });

    console.log("\n\n--- Full Response ---");
    console.log(fullText);
    console.log(`\n--- Summarization triggered: ${sawSummarization} ---`);

    expect(fullText.length).toBeGreaterThan(0);
    expect(sawSummarization).toBe(true);
  });

  it("should repair tool calls with incorrect parameters", async () => {
    console.log("\n=== Testing Tool Call Repair ===\n");

    // Define a dummy tool with strict schema
    const dummyTool = {
      description: "A test tool that requires specific parameters",
      inputSchema: z.object({
        name: z.string().describe("A person's name"),
        age: z.number().describe("A person's age in years"),
        email: z.string().email().describe("A valid email address"),
      }),
      execute: async ({
        name,
        age,
        email,
      }: {
        name: string;
        age: number;
        email: string;
      }) => {
        console.log(
          `\n[Tool Executed] name=${name}, age=${age}, email=${email}`,
        );
        return `Processed: ${name}, ${age}, ${email}`;
      },
    };

    let toolCallCount = 0;
    const toolRepairAttempted = false;
    let toolExecuted = false;

    const stream = streamResponse({
      model: "claude-haiku-4-5",
      system:
        "You are a test assistant. You must use the test_tool with these EXACT parameters: {wrongField: 'test', invalidNumber: 'not a number', missingEmail: true}. Do NOT try to fix or validate the parameters yourself - just use them exactly as given.",
      prompt:
        "Call the test_tool with the parameters I specified in the system prompt. Use those exact parameters without modification.",
      tools: {
        test_tool: dummyTool,
      },
      toolChoice: {
        type: "tool",
        toolName: "test_tool",
      },
    });

    await consumeStream(stream, {
      onTextDelta: (delta) => {
        process.stdout.write(delta.text);
      },
      onToolCall: (toolCall) => {
        toolCallCount++;
        console.log("\n\n[Tool Call]", toolCall.toolName);
        console.log("Input:", toolCall.input);

        if (toolCall.toolName === "test_tool") {
          console.log("✓ test_tool was called");
        }
      },
      onToolResult: (toolResult) => {
        console.log("\n[Tool Result]", toolResult.toolName);

        if (toolResult.toolName === "test_tool") {
          toolExecuted = true;
          console.log("✓ test_tool was executed successfully");
        }
      },
    });

    console.log("\n\n--- Stats ---");
    console.log(`Tool calls: ${toolCallCount}`);
    console.log(`Tool executed: ${toolExecuted}`);

    // If the tool was called and executed, the repair mechanism worked
    // (even if the model got it right the first time, which is unlikely)
    expect(toolCallCount).toBeGreaterThanOrEqual(1);
    expect(toolExecuted).toBe(true);
  });
});
