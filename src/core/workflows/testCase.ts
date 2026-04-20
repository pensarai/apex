import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import type { AIModel } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import type { CredentialManager } from "../credentials";
import type { AgentEventBus } from "../eventBus";
import { TestCaseAgent } from "../agents/specialized/testCase";
import type { TestCaseResponse } from "../agents/specialized/testCase";
import { runAuthenticationAgent } from "../agents/specialized/authenticationAgent";
import { createSafetyCapState } from "../agents/offSecAgent/tools/_safetyCaps";
import type { UnifiedSandbox } from "../agents/offSecAgent/tools/sandbox";
import { sessions, type SessionInfo } from "../session";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

const DEFAULT_RPS_PER_HOST = 10;
const DEFAULT_TOTAL_REQUESTS = 500;
// v1.5: widened from 5→8 min so blackbox auth (authenticate_session) +
// target UI navigation + probe all fit comfortably in one run.
const DEFAULT_WALL_CLOCK_MS = 8 * 60 * 1000;
const DEFAULT_MAX_STEPS = 80;

export interface TestCaseWorkflowInput {
  /** The user-authored test-case specification. */
  testCase: {
    id: string;
    instructions: string;
    targetUrl?: string;
    artifactFilename?: string;
    artifactContentType?: string;
    artifactSizeBytes?: number;
    /** Optional step-budget override (default 50, hard cap 200). */
    maxSteps?: number;
  };

  /**
   * Raw bytes of the attached artifact (fetched from storage by the
   * caller). When present, staged into the sandbox at /work/artifact.*
   * before the agent runs.
   */
  artifactBytes?: Buffer | Uint8Array;

  /**
   * Sandbox to stage the artifact into and use as Apex's scratch space.
   * Caller is responsible for creating + destroying it — the workflow
   * doesn't own the sandbox lifecycle so callers can pool / reuse them.
   */
  sandbox?: UnifiedSandbox;

  /**
   * Default HTTP headers merged into every outbound request to the
   * target URL (static target authentication: API keys, bearer tokens,
   * pre-baked session cookies). The agent never sees these raw.
   *
   * Use this for scenarios where auth is a static header. For
   * browser-based login flows, pass a `credentialManager` instead —
   * the agent will call `authenticate_session` to run the login.
   */
  targetAuthHeaders?: Record<string, string>;

  /**
   * In-memory credential store. When set, the agent can call
   * `authenticate_session` to run the login flow against the target
   * using the stored credentials, without ever seeing the raw secrets
   * in its prompt. Build this from `core.credentials` entries tied to
   * the project — reuses the blackbox-pentest auth pattern.
   */
  credentialManager?: CredentialManager;

  /** LLM model (default claude-sonnet-4-5). */
  model?: AIModel;

  /** Provider credentials (Bedrock, etc.). */
  authConfig?: AIAuthConfig;

  /**
   * Optional event bus. Consumers subscribe to `detection_event` events
   * (and text-delta / tool-call / subagent-* for live log) here. If the
   * caller doesn't pass one, the workflow creates a fresh bus; detection
   * events will be lost unless the caller attaches a listener to the
   * returned response object (use-case: tests).
   */
  eventBus?: AgentEventBus;

  /** Parent-driven cancellation. Composes with the workflow's internal deadline. */
  abortSignal?: AbortSignal;

  /**
   * Optional session override. When not provided, a fresh session is
   * created (recommended for isolated runs — each test case gets its
   * own findings/logs/trace directory under ~/.pensar/sessions).
   */
  session?: SessionInfo;

  /**
   * Per-run safety-cap overrides. Defaults: 10 RPS/host, 500 requests,
   * 5 min wall clock. Caller can tune for scenarios that legitimately
   * need bulk probing, but the agent's system prompt advises it to
   * stop on safety-cap violations either way.
   */
  safetyCaps?: {
    rpsPerHost?: number;
    totalRequests?: number;
    wallClockMs?: number;
  };
}

export interface TestCaseWorkflowResult {
  response: TestCaseResponse;
  session: SessionInfo;
  /** Total HTTP requests actually sent (counted by safety-cap state). */
  requestsSent: number;
  /** Wall-clock duration of the agent run, ms. */
  durationMs: number;
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

function artifactExtension(filename?: string): string {
  if (!filename) return ".bin";
  const m = filename.match(/\.([a-zA-Z0-9]+(?:\.(?:gz|xz|bz2))?)$/);
  return m ? `.${m[1].toLowerCase()}` : ".bin";
}

async function stageArtifact(
  sandbox: UnifiedSandbox,
  bytes: Buffer | Uint8Array,
  filename: string | undefined,
): Promise<string> {
  const ext = artifactExtension(filename);
  const remotePath = `/work/artifact${ext}`;
  // Use mkdir + write via base64 over execute so we don't depend on a
  // specific sandbox.uploadFile signature.
  await sandbox.execute("mkdir -p /work && chmod 700 /work", { timeout: 10 });
  const b64 = Buffer.from(bytes).toString("base64");
  // Chunk if very large — sandbox.execute has command length limits.
  const CHUNK = 64 * 1024;
  let written = 0;
  while (written < b64.length) {
    const chunk = b64.slice(written, written + CHUNK);
    const op = written === 0 ? ">" : ">>";
    await sandbox.execute(
      `printf '%s' '${chunk}' ${op} ${remotePath}.b64`,
      { timeout: 30 },
    );
    written += CHUNK;
  }
  const decode = await sandbox.execute(
    `base64 -d ${remotePath}.b64 > ${remotePath} && rm -f ${remotePath}.b64`,
    { timeout: 60 },
  );
  if (!decode.success || decode.exitCode !== 0) {
    throw new Error(
      `Failed to stage artifact into sandbox: ${decode.stderr || decode.stdout}`,
    );
  }
  return remotePath;
}

/**
 * Write a JSON summary of the run to the session directory for
 * post-hoc inspection / debugging. Best-effort.
 */
function writeRunSummary(
  session: SessionInfo,
  testCaseId: string,
  result: Omit<TestCaseWorkflowResult, "session">,
): void {
  try {
    const dir = join(session.rootPath, "test-case-runs");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, `${testCaseId}.json`),
      JSON.stringify(result, null, 2),
    );
  } catch {
    /* best-effort */
  }
}

function anySignal(
  signals: (AbortSignal | undefined)[],
): AbortSignal {
  const controller = new AbortController();
  for (const sig of signals) {
    if (!sig) continue;
    if (sig.aborted) {
      controller.abort();
      return controller.signal;
    }
    sig.addEventListener("abort", () => controller.abort(), { once: true });
  }
  return controller.signal;
}

/**
 * Execute a user-authored security test case against a target system.
 *
 * High-level flow:
 *   1. Session — create a fresh session (or reuse the caller's) for
 *      findings, logs, trace, and the run-summary JSON.
 *   2. Stage artifact — if bytes were provided and a sandbox is wired,
 *      copy them into /work/artifact.* inside the sandbox.
 *   3. Safety caps — build a fresh token-bucket / counter / deadline
 *      state. Threaded into every HTTP-emitting tool via ToolContext.
 *   4. Agent loop — spawn TestCaseAgent with the curated test-case
 *      toolset, the user's instructions, and the merged target auth
 *      headers. Emits detection_event and all streaming events to
 *      `input.eventBus`.
 *   5. Return — the agent's structured response plus some counters
 *      for operator visibility.
 *
 * Detection events are emitted during the run; callers are expected
 * to attach a listener to `input.eventBus.on("detection_event", …)`
 * BEFORE invoking this function. The workflow does not collect them
 * itself (doing so would conflate "live stream" with "batched result"
 * semantics — the caller picks which model fits their UI).
 */
export async function runTestCaseWorkflow(
  input: TestCaseWorkflowInput,
): Promise<TestCaseWorkflowResult> {
  const startedAt = Date.now();

  // 1. Session
  const session =
    input.session ??
    (await sessions.create({
      name: `test-case:${input.testCase.id}`,
      targets: input.testCase.targetUrl ? [input.testCase.targetUrl] : [],
      config: { mode: "auto" },
    }));

  // 2. Stage artifact (if we have bytes + a sandbox to host them)
  let stagedPath: string | undefined;
  if (input.artifactBytes && input.sandbox) {
    stagedPath = await stageArtifact(
      input.sandbox,
      input.artifactBytes,
      input.testCase.artifactFilename,
    );
  }

  // 3. Safety caps + internal deadline
  const wallClockMs =
    input.safetyCaps?.wallClockMs ?? DEFAULT_WALL_CLOCK_MS;
  const deadlineController = new AbortController();
  const deadline = setTimeout(() => deadlineController.abort(), wallClockMs);

  const abortSignal = anySignal([
    input.abortSignal,
    deadlineController.signal,
  ]);

  const safetyCaps = createSafetyCapState({
    rpsPerHost: input.safetyCaps?.rpsPerHost ?? DEFAULT_RPS_PER_HOST,
    totalRequests:
      input.safetyCaps?.totalRequests ?? DEFAULT_TOTAL_REQUESTS,
    wallClockMs,
    eventBus: input.eventBus,
  });

  // 4. Pre-run auth phase — the main TestCaseAgent no longer drives auth
  //    itself; the workflow orchestrates AuthenticationAgent first so that
  //    its resulting auth-data.json is already on disk by the time the
  //    main agent's prompt is built (mirrors the pentest path).
  //
  //    The session must already carry a credentialManager (populated at
  //    session creation via authCredentials in session.config); we honor
  //    the explicit input.credentialManager as the primary trigger.
  const sessionCredentialManager =
    input.credentialManager ?? session.credentialManager;
  if (sessionCredentialManager && sessionCredentialManager.size > 0) {
    if (!input.testCase.targetUrl) {
      throw new Error(
        "test-case auth phase requires a target URL — project has credentials but no resolved target",
      );
    }
    // Ensure the session object exposes the credentialManager so the
    // AuthenticationAgent picks it up (session.credentialManager is the
    // only auth source the agent consults).
    if (!session.credentialManager) {
      (session as SessionInfo & { credentialManager?: CredentialManager }).credentialManager =
        sessionCredentialManager;
    }

    const authResult = await runAuthenticationAgent({
      target: input.testCase.targetUrl,
      session,
      model: input.model ?? "claude-sonnet-4-5",
      eventBus: input.eventBus,
      authConfig: input.authConfig,
      abortSignal,
    });

    if (!authResult.success) {
      // Surface auth failure as a first-class detection event so a bad
      // login flips the run to FAIL rather than silently proceeding
      // unauthenticated and passing on a pipe break. Adapters (console's
      // createMqttEventBus) re-publish these onto MQTT for the UI.
      input.eventBus?.emit("detection_event", {
        kind: "alert_raised",
        source: "rule-engine",
        severity: "high",
        summary: `authentication failed: ${authResult.summary}`,
        data: {
          phase: "pre-run-auth",
          strategy: authResult.strategy,
          authBarrier: authResult.authBarrier,
        },
      });
      clearTimeout(deadline);
      throw new Error(`test case auth failed: ${authResult.summary}`);
    }
  }

  // 5. Build agent input and run
  const maxSteps = Math.min(input.testCase.maxSteps ?? DEFAULT_MAX_STEPS, 200);

  // Compose an auth-hint for the agent's user prompt. Agent never sees
  // raw secrets; only a summary of what static headers are applied.
  // Cookie/header state from the pre-run auth phase is injected by the
  // prompt builder reading auth-data.json directly — not via this hint.
  const hintParts: string[] = [];
  if (input.targetAuthHeaders) {
    hintParts.push(
      `Static headers applied automatically: ${Object.keys(input.targetAuthHeaders).join(", ")}`,
    );
  }
  const authHint = hintParts.length > 0 ? hintParts.join("\n") : undefined;

  const agent = new TestCaseAgent({
    testCase: {
      instructions: input.testCase.instructions,
      targetUrl: input.testCase.targetUrl,
      artifact: stagedPath
        ? {
            stagedPath,
            filename: input.testCase.artifactFilename,
            contentType: input.testCase.artifactContentType,
            sizeBytes: input.testCase.artifactSizeBytes,
          }
        : undefined,
      maxSteps,
      authHint,
    },
    session,
    sandbox: input.sandbox,
    eventBus: input.eventBus,
    model: input.model,
    authConfig: input.authConfig,
    abortSignal,
    safetyCaps,
    defaultHeaders: input.targetAuthHeaders,
    credentialManager: input.credentialManager,
    maxSteps,
  });

  try {
    const response = await agent.consume();
    const result: TestCaseWorkflowResult = {
      response,
      session,
      requestsSent: safetyCaps.totalRequests,
      durationMs: Date.now() - startedAt,
    };
    writeRunSummary(session, input.testCase.id, result);
    return result;
  } finally {
    clearTimeout(deadline);
  }
}
