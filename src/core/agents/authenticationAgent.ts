import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";
import { hasToolCall } from "ai";
import type { AIModel } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import { Session } from "../session";
import { AUTH_SUBAGENT_SYSTEM_PROMPT } from "./legacy/authenticationSubagent/prompts";
import { detectOSAndEnhancePrompt } from "./legacy/utils";
import { OffensiveSecurityAgent } from "../offensiveAgent/offensiveSecurityAgent";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuthenticationAgentInput {
  /** The target requiring authentication */
  target: string;

  /** AI model to drive the agent */
  model: AIModel;

  /** Session that provides paths */
  session: Session.SessionInfo;

  /** Optional credentials to use */
  credentials?: {
    username?: string;
    password?: string;
    apiKey?: string;
    loginUrl?: string;
  };

  /** Hints about the auth flow */
  authHints?: {
    authScheme?: string;
    csrfRequired?: boolean;
    browserRequired?: boolean;
    protectedEndpoints?: string[];
  };

  /** Optional per-provider API key overrides */
  authConfig?: AIAuthConfig;

  /** Optional callback after each agent step */
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;

  /** AbortSignal to cancel mid-run */
  abortSignal?: AbortSignal;
}

/** The typed result returned by `AuthenticationAgent.consume()`. */
export interface AuthenticationResult {
  /** Whether authentication was successful */
  success: boolean;
  /** Summary of the authentication process */
  summary: string;
}

// ---------------------------------------------------------------------------
// AuthenticationAgent
// ---------------------------------------------------------------------------

/**
 * An authentication-focused specialisation of {@link OffensiveSecurityAgent}.
 *
 * Uses a subset of tools to discover and complete authentication flows:
 * detect auth scheme, probe endpoints, simple auth, delegate to sub-agent,
 * and signal completion.
 *
 * `consume()` returns an {@link AuthenticationResult}.
 *
 * @example
 * ```ts
 * const agent = new AuthenticationAgent({
 *   target: "https://example.com",
 *   model: "claude-sonnet-4-20250514",
 *   session,
 *   credentials: { username: "admin", password: "admin" },
 * });
 *
 * const { success, summary } = await agent.consume({
 *   onTextDelta: (d) => process.stdout.write(d.text),
 * });
 *
 * console.log(success ? "Authenticated!" : "Failed");
 * ```
 */
export class AuthenticationAgent extends OffensiveSecurityAgent<AuthenticationResult> {
  constructor(opts: AuthenticationAgentInput) {
    const {
      model,
      target,
      session,
      credentials,
      authHints,
      authConfig,
      onStepFinish,
      abortSignal,
    } = opts;

    super({
      system: detectOSAndEnhancePrompt(AUTH_SUBAGENT_SYSTEM_PROMPT),
      prompt: buildAuthPrompt(target, credentials, authHints),
      model,
      session,
      target,
      authConfig,
      onStepFinish,
      abortSignal,

      activeTools: [
        // Auth flow tools
        "execute_command",
        "http_request",
        "detect_auth_scheme",
        "probe_auth_endpoints",
        "authenticate_session",
        "delegate_to_auth_subagent",
        "complete_authentication",
        // Browser automation for login forms, OAuth, SPA auth
        "browser_navigate",
        "browser_snapshot",
        "browser_screenshot",
        "browser_click",
        "browser_fill",
        "browser_evaluate",
        "browser_console",
        "browser_get_cookies",
      ],

      stopWhen: hasToolCall("complete_authentication"),

      resolveResult: async (streamResult) => {
        // Extract the result from the complete_authentication tool call
        const steps = await streamResult.steps;
        let success = false;
        let summary = "Authentication process completed.";

        for (const step of steps) {
          for (const tr of step.toolResults) {
            if (tr.toolName === "complete_authentication") {
              const trRecord = tr as unknown as Record<string, unknown>;
              const r = (trRecord.output ?? trRecord.result) as
                | Record<string, unknown>
                | undefined;
              success = (r?.authenticated as boolean) ?? false;
              summary = (r?.summary as string) ?? summary;
            }
          }
        }

        return { success, summary };
      },
    });
  }
}

// ---------------------------------------------------------------------------
// Prompt builder
// ---------------------------------------------------------------------------

function buildAuthPrompt(
  target: string,
  credentials?: AuthenticationAgentInput["credentials"],
  authHints?: AuthenticationAgentInput["authHints"]
): string {
  const parts: string[] = [`TARGET: ${target}\n`];

  if (credentials) {
    parts.push("CREDENTIALS:");
    if (credentials.username) parts.push(`- Username: ${credentials.username}`);
    if (credentials.password) parts.push(`- Password: ${credentials.password}`);
    if (credentials.apiKey) parts.push(`- API Key: [PROVIDED]`);
    if (credentials.loginUrl)
      parts.push(`- Login URL: ${credentials.loginUrl}`);
    parts.push("");
  } else {
    parts.push(
      "No credentials provided. Discover authentication requirements and attempt registration if possible.\n"
    );
  }

  if (authHints) {
    parts.push("AUTH HINTS:");
    if (authHints.authScheme)
      parts.push(`- Auth scheme: ${authHints.authScheme}`);
    if (authHints.csrfRequired) parts.push("- CSRF protection detected");
    if (authHints.browserRequired)
      parts.push("- Browser automation may be needed");
    if (authHints.protectedEndpoints?.length) {
      parts.push(
        `- Protected endpoints: ${authHints.protectedEndpoints.join(", ")}`
      );
    }
    parts.push("");
  }

  parts.push(`INSTRUCTIONS:
1. Detect the authentication scheme using detect_auth_scheme
2. If unclear, probe for auth endpoints with probe_auth_endpoints
3. Attempt authentication with authenticate_session
4. If that fails, delegate to the auth sub-agent with delegate_to_auth_subagent
5. Call complete_authentication when done (success or failure)`);

  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

export async function runAuthenticationAgent(input: AuthenticationAgentInput) {
  const agent = new AuthenticationAgent(input);

  const { success, summary } = await agent.consume({
    onTextDelta: (d) => process.stdout.write(d.text),
    onToolCall: (d) => console.log(`→ calling ${d.toolName}`),
    onToolResult: (d) => console.log(`✓ ${d.toolName} completed`),
    onError: (e) => console.error("Agent error:", e),
  });

  console.log(
    `\nAuthentication ${success ? "succeeded" : "failed"}: ${summary}`
  );
  return { success, summary };
}
