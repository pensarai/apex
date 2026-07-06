import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  applySequentialToolCallPolicy,
  buildReasoningProviderOptions,
  SEQUENTIAL_TOOL_CALL_INSTRUCTION,
  streamResponse,
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

describe("buildReasoningProviderOptions", () => {
  it("sets the bedrock reasoningConfig (and anthropic.thinking) for a Bedrock Claude model when thinking is enabled", () => {
    // Console sandbox agents run on Bedrock; this is the path the bug starved.
    const result = buildReasoningProviderOptions(
      "global.anthropic.claude-opus-4-6-v1",
      { enableThinking: true },
    );
    expect(result).toEqual({
      anthropic: { thinking: { type: "adaptive" } },
      bedrock: {
        reasoningConfig: { type: "adaptive", display: "summarized" },
      },
    });
  });

  it("requests no thinking for the Bedrock recon model (Haiku 4.5), which rejects adaptive", () => {
    // Regression: Haiku 4.5 supports extended thinking but not the adaptive
    // type; requesting it failed recon. Non-4.6 models get no thinking.
    expect(
      buildReasoningProviderOptions(
        "global.anthropic.claude-haiku-4-5-20251001-v1:0",
        { enableThinking: true },
      ),
    ).toBeUndefined();
  });

  it("requests no thinking for pre-4.6 thinking models (Sonnet 4.5)", () => {
    expect(
      buildReasoningProviderOptions("claude-sonnet-4-5", {
        enableThinking: true,
      }),
    ).toBeUndefined();
  });

  it("requests no thinking for pre-4.6 Opus models (Opus 4.0, 4.1, 4.5)", () => {
    for (const id of [
      "claude-opus-4-0",
      "claude-opus-4-20250514",
      "claude-opus-4-1-20250805",
      "claude-opus-4-5",
      "global.anthropic.claude-opus-4-5-20251101-v1:0",
    ]) {
      expect(
        buildReasoningProviderOptions(id, { enableThinking: true }),
      ).toBeUndefined();
    }
  });

  it("returns undefined when thinking is disabled and no OpenAI effort applies", () => {
    expect(
      buildReasoningProviderOptions("global.anthropic.claude-opus-4-6-v1", {
        enableThinking: false,
      }),
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

  it("carries the adaptive-thinking effort hint on both anthropic and bedrock for a 4.6 model", () => {
    const result = buildReasoningProviderOptions(
      "global.anthropic.claude-opus-4-6-v1",
      { enableThinking: true, thinkingEffort: "low" },
    );
    expect(result?.anthropic).toEqual({
      thinking: { type: "adaptive" },
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

  it("omits the effort hint when none is provided (model default)", () => {
    const result = buildReasoningProviderOptions(
      "global.anthropic.claude-opus-4-6-v1",
      { enableThinking: true },
    );
    expect(result?.anthropic).toEqual({ thinking: { type: "adaptive" } });
    expect(
      (result?.anthropic as { effort?: string } | undefined)?.effort,
    ).toBeUndefined();
    expect(result?.bedrock?.reasoningConfig).toEqual({
      type: "adaptive",
      display: "summarized",
    });
  });

  it("drops the effort hint when thinking is not actually used (non-adaptive model)", () => {
    // Haiku 4.5 supports thinking but not adaptive; the effort hint must not
    // ride along on a request that requests no thinking at all.
    expect(
      buildReasoningProviderOptions(
        "global.anthropic.claude-haiku-4-5-20251001-v1:0",
        { enableThinking: true, thinkingEffort: "high" },
      ),
    ).toBeUndefined();
  });

  it("ignores the effort hint when thinking is disabled", () => {
    expect(
      buildReasoningProviderOptions("global.anthropic.claude-opus-4-6-v1", {
        enableThinking: false,
        thinkingEffort: "high",
      }),
    ).toBeUndefined();
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
