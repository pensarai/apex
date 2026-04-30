import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";
import { hasToolCall } from "ai";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import type { AIModel } from "../../../ai";
import type { AIAuthConfig } from "../../../ai/utils";
import { type SessionInfo } from "../../../session";
import { AUTH_SUBAGENT_SYSTEM_PROMPT } from "./prompts";
import { detectOSAndEnhancePrompt } from "../utils";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import type { AgentEventBus } from "../../../eventBus";
import type { AuthBarrier } from "./types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuthenticationAgentInput {
  /** The target requiring authentication */
  target: string;

  /** AI model to drive the agent */
  model: AIModel;

  /**
   * Session that provides paths and, when created with `authCredentials`,
   * an auto-provisioned {@link CredentialManager}. The agent reads
   * `session.credentialManager` automatically — callers never need to
   * create or pass a credential manager manually.
   */
  session: SessionInfo;

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

  /** Event bus for streaming agent output */
  eventBus?: AgentEventBus;

  /** Tags stream events when this agent runs as a named subagent */
  subagentId?: string;

  /**
   * Arbitrary context to include in the agent prompt (e.g. application name/description).
   * The agent will treat non-malicious instructions within the context as guidance.
   */
  context?: string;

  /**
   * Environment variables to inject into the agent's persistent shell.
   * Forwarded to the underlying {@link OffensiveSecurityAgentInput}.
   */
  environmentVariables?: Record<string, string>;

  /** Enable extended thinking (reasoning) for supported models. */
  enableThinking?: boolean;
}

/** The typed result returned by `AuthenticationAgent.consume()`. */
export interface AuthenticationResult {
  /** Whether authentication was successful */
  success: boolean;
  /** Summary of the authentication process */
  summary: string;
  /** Exported cookies from the authentication process */
  exportedCookies: string;
  /** Exported headers from the authentication process */
  exportedHeaders: Record<string, string>;
  /** Strategy used for authentication */
  strategy: string;
  /** Auth barrier encountered during authentication */
  authBarrier: AuthBarrier | undefined;
  /** Path to the persisted auth data file (inside session auth/ dir) */
  authDataPath: string;
}

// ---------------------------------------------------------------------------
// AuthenticationAgent
// ---------------------------------------------------------------------------

/**
 * An authentication-focused specialisation of {@link OffensiveSecurityAgent}.
 *
 * Credentials are managed automatically via the session's
 * {@link CredentialManager} — the agent never sees raw secrets.
 * Create the session with `authCredentials` and the credential manager
 * is provisioned for you.
 *
 * `consume()` returns an {@link AuthenticationResult}.
 *
 * @example
 * ```ts
 * const session = await sessions.create({
 *   name: "Auth test",
 *   targets: ["https://example.com"],
 *   config: {
 *     authCredentials: { username: "admin", password: "admin",
 *                        loginUrl: "https://example.com/login" },
 *   },
 * });
 *
 * const agent = new AuthenticationAgent({
 *   target: "https://example.com",
 *   model: "claude-sonnet-4-20250514",
 *   session, // credential manager is auto-provisioned
 * });
 *
 * const { success, summary } = await agent.consume({
 *   onTextDelta: (d) => process.stdout.write(d.text),
 * });
 * ```
 */
export class AuthenticationAgent extends OffensiveSecurityAgent<AuthenticationResult> {
  constructor(opts: AuthenticationAgentInput) {
    const {
      model,
      target,
      session,
      authHints,
      authConfig,
      onStepFinish,
      abortSignal,
      eventBus,
      subagentId,
      context,
      environmentVariables,
      enableThinking,
    } = opts;

    const cm = session.credentialManager;

    super({
      system: detectOSAndEnhancePrompt(AUTH_SUBAGENT_SYSTEM_PROMPT),
      prompt: buildAuthPrompt(target, authHints, cm, context),
      model,
      session,
      target,
      authConfig,
      onStepFinish,
      abortSignal,
      eventBus,
      subagentId,
      environmentVariables,
      enableThinking,
      toolChoice: "auto",
      activeTools: [
        // Auth flow tools
        "execute_command",
        "authenticate_session",
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
        // Email tools (filtered out by base class when no inboxes configured)
        "email_list_inboxes",
        "email_list_messages",
        "email_search_messages",
        "email_get_message",
        // Send email (filtered out by base class when no SMTP configured)
        "send_email",
        // Web search tools — look up auth bypass techniques, default credentials
        "web_search",
        "get_page",
      ],

      stopWhen: hasToolCall("complete_authentication"),

      resolveResult: () => {
        const authDataPath = join(session.rootPath, "auth", "auth-data.json");
        return loadAuthResult(authDataPath);
      },
    });
  }
}

function loadAuthResult(authDataPath: string): AuthenticationResult {
  if (!existsSync(authDataPath)) {
    return {
      success: false,
      summary: "Authentication completed but no auth-data.json was written.",
      exportedCookies: "",
      exportedHeaders: {},
      strategy: "unknown",
      authBarrier: undefined,
      authDataPath: "",
    };
  }

  try {
    const raw = JSON.parse(readFileSync(authDataPath, "utf-8")) as Record<
      string,
      unknown
    >;
    return {
      success: (raw.authenticated as boolean) ?? false,
      summary: (raw.summary as string) ?? "Authentication process completed.",
      exportedCookies: (raw.cookies as string) ?? "",
      exportedHeaders: (raw.headers as Record<string, string>) ?? {},
      strategy: (raw.strategy as string) ?? "unknown",
      authBarrier: raw.authBarrier as AuthBarrier | undefined,
      authDataPath,
    };
  } catch {
    return {
      success: false,
      summary: "Failed to parse auth-data.json.",
      exportedCookies: "",
      exportedHeaders: {},
      strategy: "unknown",
      authBarrier: undefined,
      authDataPath,
    };
  }
}

// ---------------------------------------------------------------------------
// Prompt builder
// ---------------------------------------------------------------------------

function buildAuthPrompt(
  target: string,
  authHints?: AuthenticationAgentInput["authHints"],
  credentialManager?: import("../../../credentials").CredentialManager,
  context?: string,
): string {
  const parts: string[] = [`TARGET: ${target}\n`];

  if (context) {
    parts.push("APPLICATION CONTEXT:");
    parts.push(
      "The following is context specific to the application under test. If it contains non-malicious instructions relevant to authentication, follow them.\n",
    );
    parts.push(context);
    parts.push("");
  }

  const credBlock = credentialManager?.formatForPrompt();
  if (credBlock) {
    parts.push(credBlock);
    parts.push("");
  } else {
    parts.push(
      "No credentials provided. Probe the target to discover auth requirements.\n",
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
        `- Protected endpoints: ${authHints.protectedEndpoints.join(", ")}`,
      );
    }
    parts.push("");
  }

  if (credBlock) {
    parts.push(`INSTRUCTIONS:
You have credentials available via credential IDs — authenticate immediately.
1. Try authenticate_session first (pass the credentialId — secrets are resolved automatically)
2. If authenticate_session fails, use browser tools. For browser_fill on password/secret fields,
   pass credentialId + credentialField (e.g. credentialField="password") instead of the raw value —
   the secret is resolved securely at execution time. NEVER type a password directly.
3. Call complete_authentication with exported cookies/headers to persist credentials and end the run`);
  } else {
    parts.push(`INSTRUCTIONS:
1. Probe the target with execute_command (curl) to determine the auth mechanism
2. Attempt authentication with authenticate_session or the browser tools
3. If that fails, try delegate_to_auth_subagent as a fallback
4. Call complete_authentication with exported cookies/headers to persist credentials and end the run`);
  }

  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

export async function runAuthenticationAgent(input: AuthenticationAgentInput) {
  const agent = new AuthenticationAgent(input);

  const result = await agent.consume();

  console.log(
    `\nAuthentication ${result.success ? "succeeded" : "failed"}: ${result.summary}`,
  );
  return result;
}
