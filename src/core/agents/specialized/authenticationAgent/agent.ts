import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";
import { z } from "zod";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import type { AIModel } from "../../../ai";
import type { AIAuthConfig } from "../../../ai/utils";
import { type SessionInfo } from "../../../session";
import { AUTH_SUBAGENT_SYSTEM_PROMPT } from "./prompts";
import { detectOSAndEnhancePrompt } from "../utils";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import type { ConsumeCallbacks } from "../../offSecAgent/types";
import type { AuthBarrier } from "./types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuthenticationAgentInput {
  /** The target requiring authentication */
  target: string;

  /** AI model to drive the agent */
  model: AIModel;

  /** Session that provides paths */
  session: SessionInfo;

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

  /** Optional persistence callbacks for external storage integration */
  callbacks?: ConsumeCallbacks;
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
// Response schema — the agent calls "response" when done (same pattern as
// TargetedPentestAgent). complete_authentication persists auth data to disk;
// this schema captures the structured result and terminates the agent.
// ---------------------------------------------------------------------------

const AuthResponseSchema = z.object({
  success: z.boolean().describe("Whether authentication was successful"),
  summary: z
    .string()
    .describe("Brief summary of the authentication process and result"),
  strategy: z
    .string()
    .optional()
    .describe(
      "Authentication strategy used (browser, form_post, json_post, basic_auth, bearer, api_key)",
    ),
  barrierType: z
    .string()
    .optional()
    .describe(
      "If an auth barrier was encountered, its type (captcha, mfa, oauth_consent, rate_limit, unknown)",
    ),
  barrierDetails: z
    .string()
    .optional()
    .describe("Details about the auth barrier encountered"),
});

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
      toolChoice: "auto",
      activeTools: [
        // Auth flow tools
        "execute_command",
        // "http_request",
        // "detect_auth_scheme",
        // "probe_auth_endpoints",
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
        // Structured termination (same pattern as pentest agent)
        "response",
      ],

      responseSchema: AuthResponseSchema,

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
  credentials?: AuthenticationAgentInput["credentials"],
  authHints?: AuthenticationAgentInput["authHints"],
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

  if (credentials?.loginUrl || credentials?.username) {
    parts.push(`INSTRUCTIONS:
You have credentials — authenticate immediately.
1. Use authenticate_session (API) or the browser tools depending on the target
2. If authenticate_session fails, try via browser or delegate_to_auth_subagent
3. Call complete_authentication to persist credentials (success or failure)
4. Call the response tool with your final summary to end the run`);
  } else {
    parts.push(`INSTRUCTIONS:
1. Probe the target with execute_command (curl) to determine the auth mechanism
2. Attempt authentication with authenticate_session or the browser tools
3. If that fails, try delegate_to_auth_subagent as a fallback
4. Call complete_authentication to persist credentials (success or failure)
5. Call the response tool with your final summary to end the run`);
  }

  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

export async function runAuthenticationAgent(input: AuthenticationAgentInput) {
  const agent = new AuthenticationAgent(input);

  const result = await agent.consume({
    onTextDelta: (d) => input.callbacks?.onTextDelta?.(d),
    onToolCall: (d) => input.callbacks?.onToolCall?.(d),
    onToolResult: (d) => input.callbacks?.onToolResult?.(d),
    onError: (e) => input.callbacks?.onError?.(e),
    subagentCallbacks: input.callbacks?.subagentCallbacks,
  });

  console.log(
    `\nAuthentication ${result.success ? "succeeded" : "failed"}: ${result.summary}`,
  );
  return result;
}
