import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";
import { hasToolCall } from "ai";
import type {
  AIAuthConfig,
  AIModel,
  OpenAIReasoningEffort,
  ThinkingEffort,
} from "../../../ai";
import type { AgentEventBus } from "../../../eventBus";
import { createLogger } from "../../../logger/structured";
import type { SessionInfo } from "../../../session";
import { scopedLogger } from "../../../util/lazyLogger";
import { OffensiveSecurityAgent } from "../../offSecAgent";
import { detectOSAndEnhancePrompt } from "../utils";
import { AUTH_SUBAGENT_SYSTEM_PROMPT } from "./prompts";
import type { AuthBarrier } from "./types";

const log = scopedLogger(() => createLogger("authentication-agent"));

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

  /** Human-readable label for readable OTel span names (see base input). */
  subagentName?: string;

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

  /** Secret values to scrub from execute_command output. Forwarded to the underlying {@link OffensiveSecurityAgentInput}. */
  secretValues?: string[];

  /** Enable extended thinking (reasoning) for supported models. */
  enableThinking?: boolean;

  /** Adaptive-thinking effort hint (Anthropic Opus/Sonnet 4.6+); ignored elsewhere. */
  thinkingEffort?: ThinkingEffort | null;

  /** OpenAI reasoning effort for GPT/o-series reasoning models. */
  openAIReasoningEffort?: OpenAIReasoningEffort | null;
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
    const { target, authHints, context, ...base } = opts;
    const { session } = base;

    const cm = session.credentialManager;

    super({
      ...base,
      system: detectOSAndEnhancePrompt(AUTH_SUBAGENT_SYSTEM_PROMPT),
      activeTools: [
        // Auth flow tools
        "execute_command",
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
        // Mobile OTP list (filtered out by base class when no sms-passwordless cred)
        "sms_list_messages",
        // Web search tools — look up auth bypass techniques, default credentials
        "web_search",
        "get_page",
      ],
      stopWhen: hasToolCall("complete_authentication"),
      resolveResult: () =>
        loadAuthResult(join(session.rootPath, "auth", "auth-data.json")),
      target,
      prompt: buildAuthPrompt(
        target,
        authHints,
        cm,
        context,
        base.environmentVariables
          ? Object.keys(base.environmentVariables)
          : undefined,
      ),
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
  envVarNames?: string[],
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

  if (envVarNames?.length) {
    parts.push("ENVIRONMENT VARIABLES:");
    parts.push(
      `These are pre-loaded in your shell and available in every execute_command call. Reference them (e.g. $${envVarNames[0]}) — their values are hidden from you and redacted from command output, so never try to print one.`,
    );
    parts.push(envVarNames.map((n) => `- ${n}`).join("\n"));
    parts.push("");
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
    const hasSmsPasswordless = credentialManager
      ?.listReferences()
      .some((ref) => ref.additionalFieldKeys?.includes("phoneNumber"));
    const smsInstructions = hasSmsPasswordless
      ? `
If a credential has a phoneNumber additional field (Mobile OTP / sms-passwordless), phone is the login
identifier — not MFA-after-password. Immediately before filling the phone field, call sms_list_messages
with reserve=true; never pass that tool a phone number. If it returns 429, retry the reservation later as
a separate attempt without waiting in the tool. Then browser_fill credentialField="phoneNumber", click
send-code, and call sms_list_messages with sinceMs = Date.now() at that click and claim=true after a brief
execute_command sleep. If the list is empty, make one delayed list retry; if it stays empty, fail with what
you observed. Then browser_fill the OTP. Do NOT report phone_verification as a barrier for this flow.
TOTP-via-env for authenticator MFA is unchanged.`
      : "";
    parts.push(`INSTRUCTIONS:
You have credentials available via credential IDs — authenticate immediately.
1. For API/form logins, use execute_command (curl) to submit credentials and capture the Set-Cookie / token response
2. For browser-based logins, use the browser tools. For browser_fill on password/secret fields,
   pass credentialId + credentialField (e.g. credentialField="password") instead of the raw value —
   the secret is resolved securely at execution time. NEVER type a password directly.
3. Call complete_authentication with exported cookies/headers to persist credentials and end the run
${smsInstructions}
The credentials above were provided to you and have already been verified — they are SHARED across runs, so
do not modify them or their account settings. NEVER change the password, complete a password reset /
forced-password-change / account-recovery flow, or modify MFA/2FA settings (enrolling, disabling, or
resetting a second factor) for this account. If they do not authenticate (rejected, locked out, forced
password change required, email not confirmed, or an MFA prompt with no TOTP seed available), call
complete_authentication with success=false and a clear summary of why — do not attempt to recover, reset,
or rotate them. When a TOTP seed IS available, generate the code and continue; that is not a barrier. Do NOT
register a new account or self-sign-up to work around a failed login: that is not the credential under test
and only pollutes results — fail fast with success=false instead.`);
  } else {
    parts.push(`INSTRUCTIONS:
1. Probe the target with execute_command (curl) to determine the auth mechanism
2. Attempt authentication with execute_command (curl) or the browser tools
3. Call complete_authentication with exported cookies/headers to persist credentials and end the run`);
  }

  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

export async function runAuthenticationAgent(input: AuthenticationAgentInput) {
  const agent = new AuthenticationAgent(input);

  const result = await agent.consume();

  log.info(
    `Authentication ${result.success ? "succeeded" : "failed"}: ${result.summary}`,
  );
  return result;
}
