import { hasToolCall, stepCountIs } from "ai";
import type { AIModel } from "../../../ai";
import type { AIAuthConfig } from "../../../ai/utils";
import type { CredentialManager } from "../../../credentials";
import type { AgentEventBus } from "../../../eventBus";
import type { SessionInfo } from "../../../session";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import { TEST_CASE_TOOL_NAMES } from "../../offSecAgent/tools";
import type { SafetyCapState } from "../../offSecAgent/tools/_safetyCaps";
import type { UnifiedSandbox } from "../../offSecAgent/tools/sandbox";
import {
  buildTestCaseSystemPrompt,
  buildTestCaseUserPrompt,
  type BuildTestCasePromptInput,
} from "./prompts";
import { TestCaseResponseSchema, type TestCaseResponse } from "./schemas";

// v1.5: widened from 50 to 80 so browser + auth + probe scenarios fit.
// Browser flows (authenticate_session → navigate → fill → click) routinely
// consume 10-20 steps before the actual probe begins.
const DEFAULT_MAX_STEPS = 80;
const HARD_MAX_STEPS = 200;

export interface TestCaseAgentInput {
  /** The test-case specification the user authored. */
  testCase: BuildTestCasePromptInput;

  /** Apex session (provides scratch path, findings dir, trace log). */
  session: SessionInfo;

  /** Sandbox for artifact pre-flight and command execution. */
  sandbox?: UnifiedSandbox;

  /** Event bus that consumers subscribe to for detection events + logs. */
  eventBus?: AgentEventBus;

  /** LLM model (default claude-sonnet-4-5). */
  model?: AIModel;

  /** Provider credentials (Bedrock provider chain, etc.). */
  authConfig?: AIAuthConfig;

  /** Parent-driven cancellation. */
  abortSignal?: AbortSignal;

  /**
   * Per-run safety caps. Threaded into the tool context so every HTTP
   * tool enforces the same rate/request/wall-clock budget.
   */
  safetyCaps?: SafetyCapState;

  /**
   * Default headers merged into every outbound HTTP request. Use this to
   * carry target authentication (Authorization, API keys, cookies) without
   * exposing them to the agent's prompt.
   */
  defaultHeaders?: Record<string, string>;

  /** Step budget (default 80, hard cap 200). */
  maxSteps?: number;

  /** Parent subagent id (when the test-case agent is spawned from another agent). */
  subagentId?: string;

  /**
   * In-memory credential store. When set, the agent can resolve credential
   * references to full secrets without the raw values ever appearing in its
   * prompt. The `authenticate_session` tool consumes this to run the login
   * flow against the target; the agent never handles raw passwords / tokens.
   */
  credentialManager?: CredentialManager;
}

/**
 * TestCaseAgent — a tight pentest-style agent loop that executes a
 * user-authored test case against a system under test. Emits
 * `detection_event`s to the wired event bus as it observes real
 * responses from the target.
 *
 * Usage:
 * ```ts
 * const agent = new TestCaseAgent({ testCase, session, sandbox, eventBus, safetyCaps, defaultHeaders });
 * const response = await agent.consume();
 * ```
 */
export class TestCaseAgent extends OffensiveSecurityAgent<TestCaseResponse> {
  constructor(opts: TestCaseAgentInput) {
    const maxSteps = Math.min(
      opts.maxSteps ?? DEFAULT_MAX_STEPS,
      HARD_MAX_STEPS,
    );

    const activeTools = [...TEST_CASE_TOOL_NAMES, "response"];

    super({
      system: buildTestCaseSystemPrompt(maxSteps, {
        hasCredentials: !!opts.credentialManager && opts.credentialManager.size > 0,
      }),
      prompt: buildTestCaseUserPrompt({
        ...opts.testCase,
        sessionRootPath: opts.session.rootPath,
      }),
      model: opts.model ?? "claude-sonnet-4-5",
      session: opts.session,
      sandbox: opts.sandbox,
      eventBus: opts.eventBus,
      authConfig: opts.authConfig,
      abortSignal: opts.abortSignal,
      subagentId: opts.subagentId,
      safetyCaps: opts.safetyCaps,
      defaultHeaders: opts.defaultHeaders,
      credentialManager: opts.credentialManager,
      stopWhen: [hasToolCall("response"), stepCountIs(maxSteps)],
      activeTools,
      responseSchema: TestCaseResponseSchema,
    });
  }
}
