/**
 * Authentication Subagent
 *
 * Autonomous authentication agent for acquiring and maintaining credentials.
 * Follows the MetaVulnerabilityTestAgent cognitive loop pattern.
 *
 * For autonomous mode only - operator mode has separate auth handling.
 */

import {
  tool,
  hasToolCall,
  type StreamTextOnStepFinishCallback,
  type ToolSet,
} from "ai";
import { z } from "zod";
import { streamResponse, type AIModel } from "../../../ai";
import { type AIAuthConfig } from "../../../ai/utils";
import { Logger } from "../../../logger";
import { join } from "path";
import { existsSync, mkdirSync, writeFileSync } from "fs";

import { AuthStateManager } from "./authStateManager";
import {
  createAuthenticationTools,
  type HttpRequestOpts,
  type HttpRequestResult,
  type BrowserTools,
} from "./tools";
import {
  createBrowserTools,
  disconnectMcpClient,
} from "../../../offensiveAgent/tools/playwrightMcp";
import {
  AUTH_SUBAGENT_SYSTEM_PROMPT,
  AUTH_DISCOVERY_SYSTEM_PROMPT,
  buildAuthUserPrompt,
  buildAuthDiscoveryPrompt,
  CONTEXT_RECOVERY_REMINDER,
  BROWSER_FLOW_GUIDANCE,
} from "../../authenticationAgent/prompts";
import type {
  AuthenticationSubagentInput,
  AuthenticationSubagentResult,
  AuthDiscoveryInput,
  AuthDiscoveryResult,
  AuthDiscoveryEvidence,
  AuthState,
  AuthBarrier,
} from "../../authenticationAgent/types";

// =============================================================================
// Constants
// =============================================================================

const RETRY_CONFIG = {
  maxRetries: 5,
  initialDelayMs: 1000,
  maxDelayMs: 60000,
  backoffMultiplier: 2,
};

// =============================================================================
// Helpers
// =============================================================================

function isOverloadedError(error: unknown): boolean {
  const err = error as {
    message?: string;
    status?: number;
    statusCode?: number;
  };
  const message = err?.message?.toLowerCase() || "";
  const status = err?.status || err?.statusCode;
  return (
    status === 429 ||
    status === 529 ||
    status === 503 ||
    message.includes("overloaded") ||
    message.includes("rate limit") ||
    message.includes("too many requests") ||
    message.includes("capacity") ||
    message.includes("temporarily unavailable")
  );
}

function isContextTooLongError(error: unknown): boolean {
  const err = error as {
    message?: string;
    status?: number;
    statusCode?: number;
  };
  const message = err?.message?.toLowerCase() || "";
  const status = err?.status || err?.statusCode;
  return (
    status === 400 &&
    (message.includes("too long") ||
      message.includes("context length") ||
      message.includes("maximum context") ||
      message.includes("input is too long"))
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function extractHostFromTarget(target: string): string {
  try {
    const url = new URL(target);
    return url.host;
  } catch {
    // If not a valid URL, use target as-is
    return target;
  }
}

function saveAgentMessages(
  sessionRootPath: string,
  agentName: string,
  messages: unknown[],
  metadata?: Record<string, unknown>,
): string {
  const subagentsDir = join(sessionRootPath, "subagents");
  if (!existsSync(subagentsDir)) {
    mkdirSync(subagentsDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const sanitizedName = agentName.toLowerCase().replace(/[^a-z0-9-]/g, "-");
  const filename = `${sanitizedName}-${timestamp}.json`;
  const filepath = join(subagentsDir, filename);

  writeFileSync(
    filepath,
    JSON.stringify(
      {
        agentName,
        timestamp: new Date().toISOString(),
        ...metadata,
        messages,
      },
      null,
      2,
    ),
  );

  return filepath;
}

// =============================================================================
// Agent Options
// =============================================================================

export interface RunAuthenticationSubagentOpts {
  input: AuthenticationSubagentInput;
  model: AIModel;
  authConfig?: AIAuthConfig;
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
  abortSignal?: AbortSignal;
  httpRequestOverride?: (opts: HttpRequestOpts) => Promise<HttpRequestResult>;
  enableBrowserTools?: boolean;
}

// =============================================================================
// Main Agent Function
// =============================================================================

/**
 * Run the Authentication Subagent
 *
 * Acquires and validates authentication credentials for the target.
 * Uses cognitive loop reasoning pattern for reliable auth handling.
 */
export async function runAuthenticationSubagent(
  opts: RunAuthenticationSubagentOpts,
): Promise<AuthenticationSubagentResult> {
  const {
    input,
    model,
    authConfig,
    onStepFinish,
    abortSignal,
    httpRequestOverride,
    enableBrowserTools = true,
  } = opts;

  const { target, session, credentials, availableCredentials, authFlowHints } =
    input;

  // Automatically determine strategy based on what's provided
  const hasTokens =
    credentials?.tokens &&
    (credentials.tokens.bearerToken ||
      credentials.tokens.cookies ||
      credentials.tokens.sessionToken ||
      (credentials.tokens.customHeaders &&
        Object.keys(credentials.tokens.customHeaders).length > 0));

  // Use verification strategy if tokens are provided, otherwise use the specified strategy or default to "provided"
  const strategy = hasTokens ? "verification" : input.strategy || "provided";

  const targetHost = extractHostFromTarget(target);

  // Create logger
  const logger = new Logger(session, "auth-subagent.log");

  logger.info(`Starting AuthenticationSubagent for ${target}`);
  logger.info(`Strategy: ${strategy}`);
  if (credentials?.username) {
    logger.info(`Username: ${credentials.username}`);
  }

  // Create auth state manager
  const authStateManager = new AuthStateManager(
    session,
    targetHost,
    (state) => {
      logger.info(`Auth state changed: ${state.status}`);
    },
  );

  // Ensure evidence directory exists (for browser screenshots)
  const evidenceDir = join(session.rootPath, "evidence");
  if (!existsSync(evidenceDir)) {
    mkdirSync(evidenceDir, { recursive: true });
  }

  // Create browser tools if enabled
  let browserTools: BrowserTools | undefined;
  if (enableBrowserTools) {
    try {
      browserTools = createBrowserTools(
        target,
        evidenceDir,
        "auth",
        logger,
        abortSignal,
      );
      logger.info("Browser tools enabled for auth subagent");
    } catch (error) {
      logger.error(`Failed to create browser tools: ${error}`);
      // Continue without browser tools
    }
  }

  // Create authentication tools
  const authTools = createAuthenticationTools({
    session,
    authStateManager,
    httpRequest: httpRequestOverride,
    browserTools,
    logger,
    abortSignal,
  });

  // Result tracking
  let authSummary = "";
  let detectedBarrier: AuthBarrier | undefined;
  let agentReportedSuccess: boolean | undefined;

  // Completion tool to signal end of authentication
  const complete_authentication = tool({
    description: `Signal that authentication process is complete.

Call when:
- Authentication successful and validated
- Authentication failed (after reasonable attempts)
- Auth barrier detected (CAPTCHA, MFA)
- Unable to authenticate after exhausting approaches

Provide a clear summary of the authentication outcome.`,
    inputSchema: z.object({
      success: z.boolean().describe("Whether authentication was successful"),
      summary: z
        .string()
        .describe("Summary of authentication process and result"),
      authBarrier: z
        .object({
          type: z.enum([
            "captcha",
            "mfa",
            "oauth_consent",
            "rate_limit",
            "unknown",
          ]),
          details: z.string(),
        })
        .optional()
        .describe("Auth barrier if one was encountered"),
    }),
    execute: async (result) => {
      authSummary = result.summary;
      agentReportedSuccess = result.success;
      if (result.authBarrier) {
        detectedBarrier = result.authBarrier;
      }
      logger.info(
        `Authentication complete: ${result.success ? "SUCCESS" : "FAILED"}`,
      );
      return { success: true, message: "Authentication process completed." };
    },
  });

  // Build tools object with auth tools + browser tools + completion
  const tools: Record<string, unknown> = {
    ...authTools,
    complete_authentication,
  };

  // Add browser tools if available
  if (browserTools) {
    Object.assign(tools, browserTools);
  }

  // Build system prompt
  let systemPrompt = AUTH_SUBAGENT_SYSTEM_PROMPT;

  // Add context recovery reminder
  systemPrompt += "\n\n" + CONTEXT_RECOVERY_REMINDER;

  // Add browser flow guidance if browser tools enabled
  if (browserTools) {
    systemPrompt += "\n\n" + BROWSER_FLOW_GUIDANCE;
  }

  // Build user prompt
  const userPrompt = buildAuthUserPrompt({
    target,
    credentials,
    availableCredentials,
    authFlowHints,
  });

  // Messages reference for tracking
  const messagesRef: { current: unknown[] } = { current: [] };

  let attempt = 0;
  let lastError: unknown = null;

  while (attempt < RETRY_CONFIG.maxRetries) {
    attempt++;

    try {
      logger.info(
        `Running auth agent (attempt ${attempt}/${RETRY_CONFIG.maxRetries})`,
      );

      const streamResult = streamResponse({
        prompt: userPrompt,
        system: systemPrompt,
        model,
        tools: tools as ToolSet,
        authConfig,
        onStepFinish: (step) => {
          // Track messages for debugging
          if (step.toolCalls?.length > 0 || step.text) {
            messagesRef.current.push({
              role: "assistant",
              content: step.text || "",
              toolCalls: step.toolCalls,
            });
          }
          if (step.toolResults?.length > 0) {
            messagesRef.current.push({
              role: "tool",
              content: step.toolResults,
            });
          }
          // Call original onStepFinish if provided
          onStepFinish?.(step);
        },
        stopWhen: hasToolCall("complete_authentication"),
        abortSignal,
        silent: true,
      });

      // Consume stream
      for await (const chunk of streamResult.fullStream) {
        if (chunk.type === "error") {
          const error = (chunk as { error?: unknown }).error;
          if (isOverloadedError(error)) {
            throw error;
          }
        }
      }

      logger.info("Authentication agent finished");

      // Save agent messages
      try {
        const response = await streamResult.response;
        if (response.messages?.length > 0) {
          const sanitizedTarget = target
            .replace(/[^a-z0-9]/gi, "-")
            .substring(0, 30);
          saveAgentMessages(
            session.rootPath,
            `auth-subagent-${sanitizedTarget}`,
            response.messages,
            {
              target,
              strategy,
              success: authStateManager.getState().status === "active",
            },
          );
        }
      } catch (e) {
        logger.error(`Failed to save messages: ${e}`);
      }

      // Build result
      const finalState = authStateManager.getState();
      // Success is determined by either:
      // 1. AuthStateManager has active tokens (HTTP-based auth)
      // 2. Agent explicitly reported success (browser-based auth where cookies are httpOnly)
      const hasActiveTokens =
        finalState.status === "active" && finalState.tokens.length > 0;
      const success =
        hasActiveTokens || (agentReportedSuccess === true && !detectedBarrier);

      const result: AuthenticationSubagentResult = {
        success,
        authState: finalState,
        strategy,
        exportedHeaders: hasActiveTokens
          ? authStateManager.getAuthHeaders()
          : undefined,
        exportedCookies: hasActiveTokens
          ? authStateManager.getCookieString() || undefined
          : undefined,
        authBarrier: detectedBarrier,
        summary: authSummary || buildDefaultSummary(finalState, target),
      };

      // Cleanup
      if (enableBrowserTools) {
        try {
          await disconnectMcpClient();
        } catch {
          // Ignore cleanup errors
        }
      }
      authStateManager.cleanup();

      return result;
    } catch (error: unknown) {
      lastError = error;

      if (isOverloadedError(error) && attempt < RETRY_CONFIG.maxRetries) {
        const delay = Math.min(
          RETRY_CONFIG.initialDelayMs *
            Math.pow(RETRY_CONFIG.backoffMultiplier, attempt - 1),
          RETRY_CONFIG.maxDelayMs,
        );
        logger.info(`API overloaded, retrying in ${delay / 1000}s...`);
        await sleep(delay);
        continue;
      }

      if (isContextTooLongError(error)) {
        logger.error(`Context too long: ${error}`);

        // Cleanup
        if (enableBrowserTools) {
          try {
            await disconnectMcpClient();
          } catch {
            // Ignore
          }
        }
        authStateManager.cleanup();

        return {
          success: false,
          authState: authStateManager.getState(),
          strategy,
          summary: `Authentication terminated: Context exceeded model limits`,
        };
      }

      throw error;
    }
  }

  // Cleanup on failure
  if (enableBrowserTools) {
    try {
      await disconnectMcpClient();
    } catch {
      // Ignore
    }
  }
  authStateManager.cleanup();

  logger.error(
    `Failed after ${RETRY_CONFIG.maxRetries} attempts: ${lastError}`,
  );
  throw new Error(`Max retries exhausted. Last error: ${lastError}`);
}

// =============================================================================
// Helper Functions
// =============================================================================

function buildDefaultSummary(state: AuthState, target: string): string {
  switch (state.status) {
    case "active":
      return `Successfully authenticated to ${target}. Obtained ${state.tokens.length} token(s).`;
    case "expired":
      return `Authentication session for ${target} has expired.`;
    case "failed":
      return `Authentication failed for ${target}.`;
    case "authenticating":
      return `Authentication in progress for ${target}.`;
    case "pending":
    default:
      return `Authentication pending for ${target}.`;
  }
}

// =============================================================================
// Discovery Mode
// =============================================================================

export interface DiscoverAuthenticationOpts {
  input: AuthDiscoveryInput;
  model: AIModel;
  authConfig?: AIAuthConfig;
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
  abortSignal?: AbortSignal;
  enableBrowserTools?: boolean;
}

/**
 * Discover authentication requirements for an endpoint (standalone mode)
 *
 * This function analyzes an endpoint to determine:
 * 1. Whether authentication is required
 * 2. What type of authentication is used
 * 3. How to approach authentication
 *
 * Unlike runAuthenticationSubagent, this does NOT require credentials
 * and does NOT attempt to authenticate. It only performs reconnaissance.
 */
export async function discoverAuthentication(
  opts: DiscoverAuthenticationOpts,
): Promise<AuthDiscoveryResult> {
  const {
    input,
    model,
    authConfig,
    onStepFinish,
    abortSignal,
    enableBrowserTools = true,
  } = opts;

  const { target, session, additionalEndpoints } = input;
  const targetHost = extractHostFromTarget(target);

  // Create logger
  const logger = new Logger(session, "auth-discovery.log");
  logger.info(`Starting auth discovery for ${target}`);

  // Create auth state manager (for detect_auth_scheme tool)
  const authStateManager = new AuthStateManager(session, targetHost);

  // Create evidence directory for browser screenshots
  const evidenceDir = join(session.rootPath, "evidence");
  if (!existsSync(evidenceDir)) {
    mkdirSync(evidenceDir, { recursive: true });
  }

  // Create browser tools if enabled
  let browserTools: BrowserTools | undefined;
  if (enableBrowserTools) {
    try {
      browserTools = createBrowserTools(
        target,
        evidenceDir,
        "auth",
        logger,
        abortSignal,
      );
      logger.info("Browser tools enabled for auth discovery");
    } catch (error) {
      logger.error(`Failed to create browser tools: ${error}`);
    }
  }

  // Create authentication tools (only detection tools will be used)
  const authTools = createAuthenticationTools({
    session,
    authStateManager,
    browserTools,
    logger,
    abortSignal,
  });

  // Result tracking
  let discoveryResult: AuthDiscoveryResult = {
    requiresAuth: false,
    authType: "unknown",
    confidence: 0,
    reasoning: [],
    evidence: [],
    summary: "",
  };

  // Completion tool for discovery mode
  const complete_auth_discovery = tool({
    description: `Complete the authentication discovery process with your findings.

Call this when you have analyzed the endpoint and determined:
- Whether authentication is required
- What type of authentication is used
- How to approach authentication`,
    inputSchema: z.object({
      requiresAuth: z
        .boolean()
        .describe("Whether authentication is required to access the endpoint"),
      authType: z
        .enum([
          "none",
          "form",
          "json",
          "basic",
          "bearer",
          "api_key",
          "oauth",
          "unknown",
        ])
        .describe("Type of authentication detected"),
      confidence: z
        .number()
        .min(0)
        .max(100)
        .describe("Confidence level in your determination (0-100)"),
      loginUrl: z.string().optional().describe("Discovered login URL if found"),
      reasoning: z
        .array(z.string())
        .describe(
          "Step-by-step reasoning chain explaining how you arrived at this conclusion",
        ),
      recommendedApproach: z
        .string()
        .optional()
        .describe("Recommended approach for authenticating"),
      evidence: z
        .array(
          z.object({
            endpoint: z.string(),
            statusCode: z.number().optional(),
            hasLoginForm: z.boolean().optional(),
            hasAuthHeader: z.boolean().optional(),
            redirectsToLogin: z.boolean().optional(),
            loginUrl: z.string().optional(),
            notes: z.string(),
          }),
        )
        .describe("Evidence collected during discovery"),
      barriers: z
        .array(
          z.object({
            type: z.enum([
              "captcha",
              "mfa",
              "oauth_consent",
              "rate_limit",
              "unknown",
            ]),
            details: z.string(),
          }),
        )
        .optional()
        .describe("Auth barriers detected (CAPTCHA, MFA, etc.)"),
      summary: z.string().describe("Summary of your findings"),
    }),
    execute: async (result) => {
      discoveryResult = {
        requiresAuth: result.requiresAuth,
        authType: result.authType,
        confidence: result.confidence,
        loginUrl: result.loginUrl,
        reasoning: result.reasoning,
        recommendedApproach: result.recommendedApproach,
        evidence: result.evidence as AuthDiscoveryEvidence[],
        barriers: result.barriers,
        summary: result.summary,
      };
      logger.info(
        `Discovery complete: requiresAuth=${result.requiresAuth} authType=${result.authType} confidence=${result.confidence}%`,
      );
      return { success: true, message: "Auth discovery completed." };
    },
  });

  // Build tools - only include detection tools, not authentication
  const tools: Record<string, unknown> = {
    detect_auth_scheme: authTools.detect_auth_scheme,
    load_auth_flow: authTools.load_auth_flow,
    probe_auth_endpoints: authTools.probe_auth_endpoints,
    complete_auth_discovery,
  };

  // Add browser tools if available
  if (browserTools) {
    Object.assign(tools, browserTools);
  }

  // Build prompts
  const systemPrompt = AUTH_DISCOVERY_SYSTEM_PROMPT;
  const userPrompt = buildAuthDiscoveryPrompt({ target, additionalEndpoints });

  // Messages tracking
  const messagesRef: { current: unknown[] } = { current: [] };

  let attempt = 0;
  let lastError: unknown = null;

  while (attempt < RETRY_CONFIG.maxRetries) {
    attempt++;

    try {
      logger.info(
        `Running auth discovery (attempt ${attempt}/${RETRY_CONFIG.maxRetries})`,
      );

      const streamResult = streamResponse({
        prompt: userPrompt,
        system: systemPrompt,
        model,
        tools: tools as ToolSet,
        authConfig,
        onStepFinish: (step) => {
          if (step.toolCalls?.length > 0 || step.text) {
            messagesRef.current.push({
              role: "assistant",
              content: step.text || "",
              toolCalls: step.toolCalls,
            });
          }
          if (step.toolResults?.length > 0) {
            messagesRef.current.push({
              role: "tool",
              content: step.toolResults,
            });
          }
          onStepFinish?.(step);
        },
        stopWhen: hasToolCall("complete_auth_discovery"),
        abortSignal,
        silent: true,
      });

      // Consume stream
      for await (const chunk of streamResult.fullStream) {
        if (chunk.type === "error") {
          const error = (chunk as { error?: unknown }).error;
          if (isOverloadedError(error)) {
            throw error;
          }
        }
      }

      logger.info("Auth discovery agent finished");

      // Save agent messages
      try {
        const response = await streamResult.response;
        if (response.messages?.length > 0) {
          const sanitizedTarget = target
            .replace(/[^a-z0-9]/gi, "-")
            .substring(0, 30);
          saveAgentMessages(
            session.rootPath,
            `auth-discovery-${sanitizedTarget}`,
            response.messages,
            {
              target,
              requiresAuth: discoveryResult.requiresAuth,
              authType: discoveryResult.authType,
            },
          );
        }
      } catch (e) {
        logger.error(`Failed to save messages: ${e}`);
      }

      // Cleanup
      if (enableBrowserTools) {
        try {
          await disconnectMcpClient();
        } catch {
          // Ignore
        }
      }
      authStateManager.cleanup();

      return discoveryResult;
    } catch (error: unknown) {
      lastError = error;

      if (isOverloadedError(error) && attempt < RETRY_CONFIG.maxRetries) {
        const delay = Math.min(
          RETRY_CONFIG.initialDelayMs *
            Math.pow(RETRY_CONFIG.backoffMultiplier, attempt - 1),
          RETRY_CONFIG.maxDelayMs,
        );
        logger.info(`API overloaded, retrying in ${delay / 1000}s...`);
        await sleep(delay);
        continue;
      }

      if (isContextTooLongError(error)) {
        logger.error(`Context too long: ${error}`);

        if (enableBrowserTools) {
          try {
            await disconnectMcpClient();
          } catch {
            // Ignore
          }
        }
        authStateManager.cleanup();

        return {
          requiresAuth: false,
          authType: "unknown",
          confidence: 0,
          reasoning: ["Discovery terminated: Context exceeded model limits"],
          evidence: [],
          summary: "Discovery failed due to context length limits",
        };
      }

      throw error;
    }
  }

  // Cleanup on failure
  if (enableBrowserTools) {
    try {
      await disconnectMcpClient();
    } catch {
      // Ignore
    }
  }
  authStateManager.cleanup();

  logger.error(
    `Discovery failed after ${RETRY_CONFIG.maxRetries} attempts: ${lastError}`,
  );
  throw new Error(`Max retries exhausted. Last error: ${lastError}`);
}
