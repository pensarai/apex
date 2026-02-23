import { runAuthenticationAgent } from "../core/api/authentication";
import { sessions } from "../core/session";
import { AgentEventBus } from "../core/agents/offSecAgent/eventBus";
import { describe, it, expect } from "vitest";
import { config } from "dotenv";

config();

const TARGET_URL = "staging-console.pensar.dev";

describe("Authentication Agent", () => {
  it("should authenticate with credentials", async () => {
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

    const result = await runAuthenticationAgent({
      target: TARGET_URL,
      model: "claude-haiku-4-5",
      session,
      credentials: {
        username,
        password,
        loginUrl: `https://${TARGET_URL}/login`,
      },
      eventBus: new AgentEventBus(),
    });

    console.log(
      `\nResult: ${result.success ? "SUCCESS" : "FAILED"} — ${result.summary}`,
    );

    expect(result).toBeDefined();
    expect(result.summary).toBeDefined();
  });

  it("should probe target without credentials", async () => {
    const session = await sessions.create({
      name: "Test Auth No Creds",
      targets: [TARGET_URL],
    });

    const result = await runAuthenticationAgent({
      target: TARGET_URL,
      model: "claude-haiku-4-5",
      session,
      eventBus: new AgentEventBus(),
    });

    console.log(
      `\nResult: ${result.success ? "SUCCESS" : "FAILED"} — ${result.summary}`,
    );

    expect(result).toBeDefined();
    expect(result.summary).toBeDefined();
  });

  it("should authenticate with auth hints", async () => {
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

    const result = await runAuthenticationAgent({
      target: TARGET_URL,
      model: "claude-haiku-4-5",
      session,
      credentials: {
        username,
        password,
        loginUrl: `https://${TARGET_URL}/login`,
      },
      authHints: {
        authScheme: "form",
        browserRequired: true,
        protectedEndpoints: [
          `https://${TARGET_URL}/api/me`,
          `https://${TARGET_URL}/dashboard`,
        ],
      },
      eventBus: new AgentEventBus(),
    });

    console.log(
      `\nResult: ${result.success ? "SUCCESS" : "FAILED"} — ${result.summary}`,
    );

    expect(result).toBeDefined();
    expect(result.success).toBe(true);
    expect(result.summary).toBeDefined();
  });
});
