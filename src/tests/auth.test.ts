import { runAuthenticationAgent } from "../core/api/authentication";
import { sessions } from "../core/session";
import { describe, it, expect } from "vitest";
import { config } from "dotenv";

config();

const TARGET_URL = "staging-console.pensar.dev";

describe("Authentication Agent", () => {
  it("should authenticate with credential manager (auto-provisioned)", async () => {
    const username = process.env.TEST_AUTH_USERNAME;
    const password = process.env.TEST_AUTH_PASSWORD;

    if (!username || !password) {
      console.warn(
        "Skipping: TEST_AUTH_USERNAME and TEST_AUTH_PASSWORD must be set",
      );
      return;
    }

    const session = await sessions.create({
      name: "Test Auth",
      targets: [TARGET_URL],
      config: {
        authCredentials: {
          loginUrl: `https://${TARGET_URL}/login`,
          username,
          password,
        },
      },
    });

    // Session should auto-provision a CredentialManager
    expect(session.credentialManager).toBeDefined();
    expect(session.credentialManager!.size).toBe(1);

    // Prompt must contain the credential ID but NOT the raw password
    const prompt = session.credentialManager!.formatForPrompt();
    expect(prompt).toContain(username);
    expect(prompt).not.toContain(password);

    const toolCalls: { name: string; input: Record<string, unknown> }[] = [];

    const result = await runAuthenticationAgent({
      target: TARGET_URL,
      model: "claude-haiku-4-5",
      session,
      callbacks: {
        onTextDelta: (d) => process.stdout.write(d.text),
        onToolCall: (d) => {
          toolCalls.push({ name: d.toolName, input: d.input as Record<string, unknown> });
          console.log(
            `\n→ calling ${d.toolName}\n  ${JSON.stringify(d.input, null, 2)}`,
          );
        },
        onToolResult: (d) => console.log(`✓ ${d.toolName} completed`),
        onError: (e) => console.error("Agent error:", e),
      },
    });

    console.log(
      `\nResult: ${result.success ? "SUCCESS" : "FAILED"} — ${result.summary}`,
    );

    expect(result).toBeDefined();
    expect(result.summary).toBeDefined();

    // Verify the agent never typed the raw password in browser_fill
    const browserFills = toolCalls.filter((t) => t.name === "browser_fill");
    for (const fill of browserFills) {
      expect(
        fill.input.value !== password,
        `browser_fill should use credentialId, not raw password`,
      ).toBe(true);
    }
  });

  it("should probe target without credentials", async () => {
    const session = await sessions.create({
      name: "Test Auth No Creds",
      targets: [TARGET_URL],
    });

    // No authCredentials → no credential manager
    expect(session.credentialManager).toBeUndefined();

    const result = await runAuthenticationAgent({
      target: TARGET_URL,
      model: "claude-haiku-4-5",
      session,
      callbacks: {
        onTextDelta: (d) => process.stdout.write(d.text),
        onToolCall: (d) =>
          console.log(
            `\n→ calling ${d.toolName}\n  ${JSON.stringify(d.input, null, 2)}`,
          ),
        onToolResult: (d) => console.log(`✓ ${d.toolName} completed`),
        onError: (e) => console.error("Agent error:", e),
      },
    });

    console.log(
      `\nResult: ${result.success ? "SUCCESS" : "FAILED"} — ${result.summary}`,
    );

    expect(result).toBeDefined();
    expect(result.summary).toBeDefined();
  });

  it("should authenticate with auth hints (credential manager auto-provisioned)", async () => {
    const username = process.env.TEST_AUTH_USERNAME;
    const password = process.env.TEST_AUTH_PASSWORD;

    if (!username || !password) {
      console.warn(
        "Skipping: TEST_AUTH_USERNAME and TEST_AUTH_PASSWORD must be set",
      );
      return;
    }

    const session = await sessions.create({
      name: "Test Auth With Hints",
      targets: [TARGET_URL],
      config: {
        authCredentials: {
          loginUrl: `https://${TARGET_URL}/login`,
          username,
          password,
        },
      },
    });

    expect(session.credentialManager).toBeDefined();

    const toolCalls: { name: string; input: Record<string, unknown> }[] = [];

    const result = await runAuthenticationAgent({
      target: TARGET_URL,
      model: "claude-haiku-4-5",
      session,
      authHints: {
        authScheme: "form",
        browserRequired: true,
        protectedEndpoints: [
          `https://${TARGET_URL}/api/me`,
          `https://${TARGET_URL}/dashboard`,
        ],
      },
      callbacks: {
        onTextDelta: (d) => process.stdout.write(d.text),
        onToolCall: (d) => {
          toolCalls.push({ name: d.toolName, input: d.input as Record<string, unknown> });
          console.log(
            `\n→ calling ${d.toolName}\n  ${JSON.stringify(d.input, null, 2)}`,
          );
        },
        onToolResult: (d) => console.log(`✓ ${d.toolName} completed`),
        onError: (e) => console.error("Agent error:", e),
      },
    });

    console.log(
      `\nResult: ${result.success ? "SUCCESS" : "FAILED"} — ${result.summary}`,
    );

    expect(result).toBeDefined();
    expect(result.success).toBe(true);
    expect(result.summary).toBeDefined();

    const browserFills = toolCalls.filter((t) => t.name === "browser_fill");
    for (const fill of browserFills) {
      expect(
        fill.input.value !== password,
        `browser_fill should use credentialId, not raw password`,
      ).toBe(true);
    }
  });
});
