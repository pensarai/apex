import { runAuthenticationAgent } from "../core/api/authentication";
import { sessions } from "../core/session";
import { describe, it, expect } from "vitest";
import { config } from "dotenv";

config();

const TARGET_URL = "staging-console.pensar.dev";

describe("Authentication Agent — Cookie Export", () => {
  it(
    "should export cookies and/or headers after successful authentication",
    async () => {
      const username = process.env.TEST_AUTH_USERNAME;
      const password = process.env.TEST_AUTH_PASSWORD;

      if (!username || !password) {
        console.warn(
          "Skipping: TEST_AUTH_USERNAME and TEST_AUTH_PASSWORD must be set",
        );
        return;
      }

      const session = await sessions.create({
        name: "Test Auth Cookie Export",
        targets: [TARGET_URL],
        config: {
          authCredentials: {
            loginUrl: `https://${TARGET_URL}/login`,
            username,
            password,
          },
        },
      });

      // Session auto-provisions credential manager — password must not be in prompt
      expect(session.credentialManager).toBeDefined();
      expect(session.credentialManager!.formatForPrompt()).not.toContain(
        password,
      );

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
            toolCalls.push({
              name: d.toolName,
              input: d.input as Record<string, unknown>,
            });
            console.log(
              `\n→ calling ${d.toolName}\n  ${JSON.stringify(d.input, null, 2)}`,
            );
          },
          onToolResult: (d) => {
            const output =
              (d as Record<string, unknown>).output ??
              (d as Record<string, unknown>).result;
            console.log(
              `✓ ${d.toolName} completed\n  result: ${JSON.stringify(output, null, 2)}`,
            );
          },
          onError: (e) => console.error("Agent error:", e),
        },
      });

      console.log("\n========== AUTH RESULT ==========");
      console.log("success:", result.success);
      console.log("summary:", result.summary);
      console.log("strategy:", result.strategy);
      console.log("exportedCookies:", result.exportedCookies);
      console.log(
        "exportedHeaders:",
        JSON.stringify(result.exportedHeaders, null, 2),
      );
      console.log("authDataPath:", result.authDataPath);
      console.log("authBarrier:", result.authBarrier);
      console.log("=================================\n");

      expect(result.success).toBe(true);

      const hasCookies =
        typeof result.exportedCookies === "string" &&
        result.exportedCookies.length > 0;
      const hasHeaders =
        result.exportedHeaders != null &&
        Object.keys(result.exportedHeaders).length > 0;

      expect(
        hasCookies || hasHeaders,
        `Expected at least one of exportedCookies or exportedHeaders to be present.\n` +
          `  exportedCookies: ${JSON.stringify(result.exportedCookies)}\n` +
          `  exportedHeaders: ${JSON.stringify(result.exportedHeaders)}`,
      ).toBe(true);

      if (hasCookies) {
        expect(result.exportedCookies).toMatch(/\w+=\S+/);
        console.log(
          "Cookie names found:",
          result.exportedCookies
            .split(";")
            .map((c) => c.trim().split("=")[0])
            .filter(Boolean),
        );
      }

      if (hasHeaders) {
        const headerKeys = Object.keys(result.exportedHeaders);
        console.log("Header keys found:", headerKeys);
        for (const key of headerKeys) {
          expect(result.exportedHeaders[key]).toBeTruthy();
        }
      }

      expect(result.strategy).toBeDefined();
      expect(result.strategy).not.toBe("unknown");

      // Verify no raw password in browser_fill calls
      const browserFills = toolCalls.filter((t) => t.name === "browser_fill");
      for (const fill of browserFills) {
        expect(
          fill.input.value !== password,
          `browser_fill should use credentialId, not raw password`,
        ).toBe(true);
      }
    },
    { timeout: 300_000 },
  );
});
