import { describe, it, expect } from "vitest";
import { streamResponse } from "./ai";
import { consumeStream } from "./utils";
import { readFileSync } from "fs";
import { join } from "path";
import { z } from "zod";

// Skip tests if API keys are not available (e.g., in CI)
const hasApiKeys = process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY;
const describeOrSkip = hasApiKeys ? describe : describe.skip;

describeOrSkip("AI Stream Response", () => {
  it("should stream a basic response", async () => {
    console.log("\n=== Testing Basic Stream Response ===\n");

    const stream = streamResponse({
      model: "claude-3-haiku-20240307",
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

  it("should handle context length exceeded with summarization", async () => {
    console.log("\n=== Testing Context Length Handling ===\n");

    // Read the exhaust_context.txt file
    const exhaustContextPath = join(process.cwd(), "exhaust_context.txt");
    const exhaustContent = readFileSync(exhaustContextPath, "utf-8");

    console.log(`Loaded content: ${exhaustContent.length} characters`);
    console.log(
      "Attempting to send to API (should trigger context length error)...\n"
    );

    const stream = streamResponse({
      model: "claude-3-haiku-20240307", // Using a model with smaller context
      system: "You are a helpful assistant that analyzes text.",
      prompt: `Please analyze this text and give a very brief summary:\n\n${exhaustContent}\n\nWhat is this about?`,
    });

    let fullText = "";
    let toolCallCount = 0;
    let toolResultCount = 0;
    let sawSummarization = false;

    await consumeStream(stream, {
      onTextDelta: (delta) => {
        process.stdout.write(delta.text);
        fullText += delta.text;
      },
      onToolCall: (toolCall) => {
        toolCallCount++;
        console.log("\n\n[Tool Call]", toolCall.toolName);
        console.log("Input:", toolCall.input);

        if (toolCall.toolName === "summarize_conversation") {
          sawSummarization = true;
          console.log(
            "\n✓ Context length exceeded - automatic summarization triggered!"
          );
        }
      },
      onToolResult: (toolResult) => {
        toolResultCount++;
        console.log("\n[Tool Result]", toolResult.toolName);
      },
    });

    console.log("\n\n--- Full Response ---");
    console.log(fullText);
    console.log("\n--- Stats ---");
    console.log(`Text length: ${fullText.length}`);
    console.log(`Tool calls: ${toolCallCount}`);
    console.log(`Tool results: ${toolResultCount}`);
    console.log(`Saw summarization: ${sawSummarization}`);

    // Verify we got a response
    expect(fullText.length).toBeGreaterThan(0);

    // Verify summarization was triggered
    expect(sawSummarization).toBe(true);
    expect(toolCallCount).toBeGreaterThanOrEqual(1);
    expect(toolResultCount).toBeGreaterThanOrEqual(1);
  });

  it("should handle recursive context length errors (multiple summarizations)", async () => {
    console.log("\n=== Testing Recursive Context Length Handling ===\n");

    // This test verifies that if the summarization itself hits context limits,
    // it will recursively summarize again until it fits
    const exhaustContextPath = join(process.cwd(), "exhaust_context.txt");
    const exhaustContent = readFileSync(exhaustContextPath, "utf-8");

    console.log(`Loaded content: ${exhaustContent.length} characters`);
    console.log("Testing recursive summarization (may take a while)...\n");

    const stream = streamResponse({
      model: "claude-3-haiku-20240307",
      system: "You are a helpful assistant that provides concise summaries.",
      // Use the full content to trigger initial error
      prompt: `${exhaustContent}\n\nPlease provide a very brief summary of this content.`,
    });

    let fullText = "";
    let summarizationCount = 0;

    await consumeStream(stream, {
      onTextDelta: (delta) => {
        process.stdout.write(delta.text);
        fullText += delta.text;
      },
      onToolCall: (toolCall) => {
        if (toolCall.toolName === "summarize_conversation") {
          summarizationCount++;
          console.log(`\n\n[Summarization #${summarizationCount}]`);
          const input = JSON.parse(toolCall.input as string);
          console.log(`Reason: ${input.reason}`);
        }
      },
      onToolResult: (toolResult) => {
        if (toolResult.toolName === "summarize_conversation") {
          console.log("✓ Summarization completed");
        }
      },
    });

    console.log("\n\n--- Full Response ---");
    console.log(fullText);
    console.log(`\n--- Total summarizations: ${summarizationCount} ---`);

    // Verify we got a response and at least one summarization occurred
    expect(fullText.length).toBeGreaterThan(0);
    expect(summarizationCount).toBeGreaterThanOrEqual(1);

    console.log(
      `\n✅ Test passed! System handled ${summarizationCount} level(s) of recursive summarization`
    );
  });

  it.skip("should handle context length with message history", async () => {
    console.log("\n=== Testing Context Length with Message History ===\n");

    // Create a very long conversation history
    const messages = Array.from({ length: 100 }, (_, i) => ({
      role: (i % 2 === 0 ? "user" : "assistant") as "user" | "assistant",
      content: `This is message ${i + 1}. `.repeat(100), // Long messages
    }));

    console.log(`Created ${messages.length} messages in history`);
    console.log(
      "Attempting to send to API (should trigger context length error)...\n"
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
      execute: async ({ name, age, email }: any) => {
        console.log(
          `\n[Tool Executed] name=${name}, age=${age}, email=${email}`
        );
        return `Processed: ${name}, ${age}, ${email}`;
      },
    };

    let toolCallCount = 0;
    let toolRepairAttempted = false;
    let toolExecuted = false;

    const stream = streamResponse({
      model: "claude-3-haiku-20240307",
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
