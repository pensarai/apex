#!/usr/bin/env tsx

/**
 * Auth CLI Script
 *
 * Standalone script to run the authentication subagent.
 * Supports authentication with credentials, token verification, and discovery-only mode.
 *
 * Usage:
 *   # Discovery only (no credentials)
 *   tsx scripts/auth.ts --target https://example.com/api/users --discover-only
 *
 *   # With credentials
 *   tsx scripts/auth.ts --target https://example.com --username admin --password admin123
 *
 *   # Verify existing token
 *   tsx scripts/auth.ts --target https://example.com --bearer "eyJ..."
 *
 *   # No credentials (probe for registration)
 *   tsx scripts/auth.ts --target https://example.com
 */

import { sessions } from "../src/core/session";
import type { AIModel } from "../src/core/ai";
import type { AuthCredentials } from "../src/core/agents/specialized/authenticationAgent/types";
import { existsSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import { runAuthenticationAgent } from "../src/core/api";
import { config } from "dotenv";

config();

interface AuthOptions {
  target: string;
  model?: AIModel;
  username?: string;
  password?: string;
  apiKey?: string;
  bearer?: string;
  cookies?: string;
  headers?: Record<string, string>;
  protectedEndpoints?: string[];
  noBrowser?: boolean;
  discoverOnly?: boolean;
}

async function runAuth(options: AuthOptions): Promise<void> {
  let username: string | undefined = undefined;
  let password: string | undefined = undefined;
  const {
    target,
    model = "claude-sonnet-4-5" as AIModel,
    username: usernameInput,
    password: passwordInput,
    apiKey,
    bearer,
    cookies,
    headers,
    protectedEndpoints,
    noBrowser = false,
    discoverOnly = false,
  } = options;

  username = usernameInput || process.env.TEST_AUTH_USERNAME;
  password = passwordInput || process.env.TEST_AUTH_PASSWORD;

  console.log("=".repeat(80));
  console.log("AUTHENTICATION");
  console.log("=".repeat(80));
  console.log(`Target: ${target}`);
  console.log(`Model: ${model}`);
  console.log(`Browser Tools: ${noBrowser ? "Disabled" : "Enabled"}`);
  console.log(
    `Mode: ${discoverOnly ? "Discovery Only" : "Full Authentication"}`,
  );

  if (username) console.log(`Username: ${username}`);
  if (password) console.log(`Password: [PROVIDED - ${password.length} chars]`);
  if (apiKey) console.log(`API Key: [PROVIDED - ${apiKey.length} chars]`);
  if (bearer) console.log(`Bearer Token: [PROVIDED - ${bearer.length} chars]`);
  if (cookies) console.log(`Cookies: [PROVIDED - ${cookies.length} chars]`);
  if (headers)
    console.log(`Custom Headers: ${Object.keys(headers).join(", ")}`);
  if (protectedEndpoints?.length)
    console.log(`Protected Endpoints: ${protectedEndpoints.join(", ")}`);
  console.log();

  try {
    // Create session
    const session = await sessions.create({
      targets: [target],
      name: "auth-session",
      prefix: "auth",
    });

    console.log(`Session ID: ${session.id}`);
    console.log(`Session Path: ${session.rootPath}`);
    console.log();

    // Ensure auth directory exists
    const authDir = join(session.rootPath, "auth");
    if (!existsSync(authDir)) {
      mkdirSync(authDir, { recursive: true });
    }

    // ===========================================================================
    // Discovery-only mode
    // ===========================================================================
    if (discoverOnly) {
      console.log("=".repeat(80));
      console.log("DISCOVERY OUTPUT");
      console.log("=".repeat(80));
      console.log();

      const run = runAuthenticationAgent({
        session,
        model: model as AIModel,
        target,
        credentials: {
          username,
          password,
        },
      });

      for await (const event of run) {
        switch (event.type) {
          case "text-delta":
            process.stdout.write(event.data.text);
            break;
          case "tool-call":
            console.log(`→ calling ${event.data.toolName}`);
            break;
          case "tool-result":
            console.log(`✓ ${event.data.toolName} completed`);
            break;
          case "error":
            console.error("Agent error:", event.error);
            break;
        }
      }

      const result = await run.result;

      console.log();
      console.log("=".repeat(80));
      console.log("DISCOVERY RESULTS");
      console.log("=".repeat(80));
      console.log();

      console.log("Summary:");
      console.log(`  ${result.summary}`);
      console.log();

      // Save discovery results
      const discoveryPath = join(authDir, "discovery.json");
      writeFileSync(discoveryPath, JSON.stringify(result, null, 2));
      console.log(`Discovery results saved to: ${discoveryPath}`);

      return;
    }

    // ===========================================================================
    // Full authentication mode
    // ===========================================================================
    console.log("=".repeat(80));
    console.log("AUTHENTICATION OUTPUT");
    console.log("=".repeat(80));
    console.log();

    // Build credentials object
    const credentials: AuthCredentials = {};

    if (username) credentials.username = username;
    if (password) credentials.password = password;
    if (apiKey) credentials.apiKey = apiKey;

    // Handle pre-existing tokens
    if (bearer || cookies || headers) {
      credentials.tokens = {};
      if (bearer) credentials.tokens.bearerToken = bearer;
      if (cookies) credentials.tokens.cookies = cookies;
      if (headers) credentials.tokens.customHeaders = headers;
    }

    // Check if we have any credentials at all
    const hasCredentials = username || apiKey || bearer || cookies || headers;

    if (!hasCredentials) {
      console.log(
        "No credentials provided. Will discover auth requirements and probe for registration.",
      );
      console.log();
    }

    const result = await runAuthenticationAgent({
      target,
      session,
      credentials: hasCredentials ? credentials : undefined,
      model: model as AIModel,
    }).result;

    console.log();
    console.log("=".repeat(80));
    console.log("AUTHENTICATION RESULTS");
    console.log("=".repeat(80));
    console.log();

    console.log(`Success: ${result.success ? "YES" : "NO"}`);
    console.log(`Strategy: ${result.strategy}`);
    console.log();

    if (
      result.exportedHeaders &&
      Object.keys(result.exportedHeaders).length > 0
    ) {
      console.log("Exported Headers:");
      for (const [name, value] of Object.entries(result.exportedHeaders)) {
        console.log(
          `  ${name}: ${value.slice(0, 50)}${value.length > 50 ? "..." : ""}`,
        );
      }
      console.log();
    }

    if (result.exportedCookies) {
      console.log("Exported Cookies:");
      console.log(
        `  ${result.exportedCookies.slice(0, 100)}${result.exportedCookies.length > 100 ? "..." : ""}`,
      );
      console.log();
    }

    if (result.authBarrier) {
      console.log("Auth Barrier Detected:");
      console.log(`  Type: ${result.authBarrier.type}`);
      console.log(`  Details: ${result.authBarrier.details}`);
      console.log();
    }

    console.log("Summary:");
    console.log(`  ${result.summary}`);
    console.log();

    // Save tokens to session
    if (result.success) {
      const tokensPath = join(authDir, "tokens.json");
      writeFileSync(
        tokensPath,
        JSON.stringify(
          {
            success: true,
            headers: result.exportedHeaders,
            cookies: result.exportedCookies,
          },
          null,
          2,
        ),
      );
      console.log(`Tokens saved to: ${tokensPath}`);
    }

    // Save auth flow documentation
    const authFlowPath = join(authDir, "auth-flow.json");
    writeFileSync(
      authFlowPath,
      JSON.stringify(
        {
          target,
          success: result.success,
          strategy: result.strategy,
          authBarrier: result.authBarrier,
          summary: result.summary,
          documentedAt: new Date().toISOString(),
        },
        null,
        2,
      ),
    );
    console.log(`Auth flow documented at: ${authFlowPath}`);

    console.log();
    console.log("=".repeat(80));
    console.log("AUTHENTICATION COMPLETED");
    console.log("=".repeat(80));
    console.log(`Session Path: ${session.rootPath}`);
    console.log(`Logs: ${session.rootPath}/logs/auth-subagent.log`);
    console.log();
  } catch (error: unknown) {
    console.error("=".repeat(80));
    console.error("AUTHENTICATION FAILED");
    console.error("=".repeat(80));
    console.error(
      `Error: ${error instanceof Error ? error.message : String(error)}`,
    );
    if (error instanceof Error && error.stack) {
      console.error(`Stack: ${error.stack}`);
    }
    if (error instanceof Error && error.cause) {
      console.error(`Cause: ${JSON.stringify(error.cause)}`);
    }
    console.error();
    throw error;
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.error("Usage: tsx scripts/auth.ts --target <url> [options]");
    console.error();
    console.error("Required:");
    console.error(
      "  --target <url>           Target URL to authenticate against",
    );
    console.error();
    console.error("Credentials (optional):");
    console.error("  --username <user>        Username for login");
    console.error("  --password <pass>        Password for login");
    console.error("  --api-key <key>          API key");
    console.error("  --bearer <token>         Bearer token to verify");
    console.error("  --cookies <string>       Cookies to verify");
    console.error(
      '  --headers <json>         Custom headers as JSON (e.g., \'{"X-API-Key":"abc"}\')',
    );
    console.error();
    console.error("Options:");
    console.error(
      "  --model <model>          AI model (default: claude-sonnet-4-5)",
    );
    console.error(
      "                           Options: claude-sonnet-4-5, claude-opus-4, claude-haiku-4",
    );
    console.error(
      "  --endpoints <urls>       Comma-separated protected endpoints to test tokens against",
    );
    console.error("  --no-browser             Disable browser tools");
    console.error(
      "  --discover-only          Only discover auth requirements, don't authenticate",
    );
    console.error();
    console.error("Examples:");
    console.error("  # Discovery only (no credentials)");
    console.error(
      "  tsx scripts/auth.ts --target https://example.com/api --discover-only",
    );
    console.error();
    console.error("  # With username/password");
    console.error(
      '  tsx scripts/auth.ts --target https://example.com --username admin --password "secret"',
    );
    console.error();
    console.error("  # Verify a bearer token");
    console.error(
      '  tsx scripts/auth.ts --target https://example.com/api --bearer "eyJ..."',
    );
    console.error();
    console.error("  # Verify cookies");
    console.error(
      '  tsx scripts/auth.ts --target https://example.com --cookies "session=abc123"',
    );
    console.error();
    console.error("  # No credentials (probes for registration)");
    console.error("  tsx scripts/auth.ts --target https://example.com");
    console.error();
    console.error("  # With custom headers (API key, etc.)");
    console.error(
      '  tsx scripts/auth.ts --target https://api.example.com --headers \'{"X-API-Key":"abc123"}\'',
    );
    console.error();
    console.error("  # With protected endpoints for token verification");
    console.error(
      '  tsx scripts/auth.ts --target https://api.example.com --bearer "token" --endpoints "/api/data,/api/users"',
    );
    console.error();
    process.exit(args.length === 0 ? 1 : 0);
  }

  // Parse arguments
  const targetIndex = args.indexOf("--target");
  const modelIndex = args.indexOf("--model");
  const usernameIndex = args.indexOf("--username");
  const passwordIndex = args.indexOf("--password");
  const apiKeyIndex = args.indexOf("--api-key");
  const bearerIndex = args.indexOf("--bearer");
  const cookiesIndex = args.indexOf("--cookies");
  const headersIndex = args.indexOf("--headers");
  const endpointsIndex = args.indexOf("--endpoints");
  const noBrowser = args.includes("--no-browser");
  const discoverOnly = args.includes("--discover-only");

  if (targetIndex === -1) {
    console.error("Error: --target is required");
    process.exit(1);
  }

  const target = args[targetIndex + 1];
  if (!target) {
    console.error("Error: --target must be followed by a URL");
    process.exit(1);
  }

  let model: AIModel | undefined;
  if (modelIndex !== -1) {
    const modelArg = args[modelIndex + 1];
    if (!modelArg) {
      console.error("Error: --model must be followed by a model name");
      process.exit(1);
    }
    model = modelArg as AIModel;
  }

  let username: string | undefined;
  if (usernameIndex !== -1) {
    username = args[usernameIndex + 1];
    if (!username) {
      console.error("Error: --username must be followed by a value");
      process.exit(1);
    }
  }

  let password: string | undefined;
  if (passwordIndex !== -1) {
    password = args[passwordIndex + 1];
    if (!password) {
      console.error("Error: --password must be followed by a value");
      process.exit(1);
    }
  }

  let apiKey: string | undefined;
  if (apiKeyIndex !== -1) {
    apiKey = args[apiKeyIndex + 1];
    if (!apiKey) {
      console.error("Error: --api-key must be followed by a value");
      process.exit(1);
    }
  }

  let bearer: string | undefined;
  if (bearerIndex !== -1) {
    bearer = args[bearerIndex + 1];
    if (!bearer) {
      console.error("Error: --bearer must be followed by a token");
      process.exit(1);
    }
  }

  let cookies: string | undefined;
  if (cookiesIndex !== -1) {
    cookies = args[cookiesIndex + 1];
    if (!cookies) {
      console.error("Error: --cookies must be followed by a cookie string");
      process.exit(1);
    }
  }

  let headers: Record<string, string> | undefined;
  if (headersIndex !== -1) {
    const headersArg = args[headersIndex + 1];
    if (!headersArg) {
      console.error("Error: --headers must be followed by a JSON object");
      process.exit(1);
    }
    try {
      headers = JSON.parse(headersArg);
    } catch {
      console.error(
        'Error: --headers must be valid JSON (e.g., \'{"X-API-Key":"abc123"}\')',
      );
      process.exit(1);
    }
  }

  let protectedEndpoints: string[] | undefined;
  if (endpointsIndex !== -1) {
    const endpointsArg = args[endpointsIndex + 1];
    if (!endpointsArg) {
      console.error(
        "Error: --endpoints must be followed by comma-separated URLs",
      );
      process.exit(1);
    }
    protectedEndpoints = endpointsArg
      .split(",")
      .map((e) => e.trim())
      .filter(Boolean);
  }

  try {
    await runAuth({
      target,
      ...(model && { model }),
      ...(username && { username }),
      ...(password && { password }),
      ...(apiKey && { apiKey }),
      ...(bearer && { bearer }),
      ...(cookies && { cookies }),
      ...(headers && { headers }),
      ...(protectedEndpoints && { protectedEndpoints }),
      noBrowser,
      discoverOnly,
    });
  } catch (error: unknown) {
    console.error(
      "Fatal error:",
      error instanceof Error ? error.message : String(error),
    );
    process.exit(1);
  }
}

// Run if called directly
main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});

export { runAuth };
