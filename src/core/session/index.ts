import type { ModelMessage } from "ai";
import z from "zod";
import path from "path";
import os from "os";
import { existsSync, readFileSync } from "fs";
import * as Identifier from "../id/id";
import { getCurrentVersion } from "../installation";
import * as Storage from "../storage";
import type { Message } from "../messages/types";
import { RateLimiter } from "../services/rateLimiter";
import { CredentialManager } from "../credentials";
import {
  ToolsetStateSchema,
  type ToolsetState,
  toggleTool as toolsetToggle,
} from "../toolset";
import type { AIModel } from "../ai/ai";
import type { AIAuthConfig } from "../ai/utils";
import { generateRandomName, generateSessionName } from "../../util/name";

/**
 * Default outcome guidance (safe, non-destructive)
 */
export const DEFAULT_OUTCOME_GUIDANCE =
  "Prove the exploit can be run but do not exfiltrate data or cause any harm to the system. " +
  "Create proof-of-concept exploits that demonstrate the vulnerability exists without causing damage.";

/**
 * Exfil-mode outcome guidance (extract flags / sensitive data)
 */
export const EXFIL_OUTCOME_GUIDANCE =
  "Exfiltrate data to extract the flag value. " +
  "Create proof-of-concept exploits that successfully extract the flag from the target system.";

/**
 * Default headers for pensar-apex
 */
export const DEFAULT_OFFENSIVE_HEADERS: Record<string, string> = {
  "User-Agent": "pensar-apex",
};

const AuthCredentialsObject = z.object({
  // Username/password auth
  username: z.string().optional(),
  password: z.string().optional(),
  loginUrl: z.string().optional(),
  additionalFields: z.record(z.string(), z.string()).optional(),
  // API key auth
  apiKey: z.string().optional(),
  // Credential identity metadata
  role: z.string().optional(),
  context: z.string().optional(),
  // Pre-existing tokens for verification
  tokens: z
    .object({
      bearerToken: z.string().optional(),
      cookies: z.string().optional(),
      sessionToken: z.string().optional(),
      customHeaders: z.record(z.string(), z.string()).optional(),
    })
    .optional(),
});

export type AuthCredentials = z.infer<typeof AuthCredentialsObject>;

const ScopeConstraintsObject = z.object({
  allowedHosts: z.string().array().optional(),
  allowedPorts: z.number().array().optional(),
  strictScope: z.boolean().optional(),
});

export type ScopeConstraints = z.infer<typeof ScopeConstraintsObject>;

const OffensiveHeadersConfigObject = z.object({
  mode: z.enum(["none", "default", "custom"]),
  headers: z.record(z.string(), z.string()).optional(),
});

export type OffensiveHeadersConfig = z.infer<
  typeof OffensiveHeadersConfigObject
>;

const OperatorSettingsObject = z.object({
  initialMode: z.enum(["plan", "manual", "auto"]).default("manual"),
  requireApproval: z.boolean().default(true),
  enableSuggestions: z.boolean().default(true),
});

export type OperatorSettings = z.infer<typeof OperatorSettingsObject>;

const EmailInboxConfigObject = z.discriminatedUnion("provider", [
  z.object({
    provider: z.literal("gmail"),
    id: z.string(),
    name: z.string(),
    emailAddress: z.string(),
    accessToken: z.string(),
    refreshToken: z.string(),
    clientId: z.string().optional(),
    clientSecret: z.string().optional(),
    tokenExpiry: z.number().optional(),
  }),
  z.object({
    provider: z.literal("outlook"),
    id: z.string(),
    name: z.string(),
    emailAddress: z.string(),
    accessToken: z.string(),
    refreshToken: z.string(),
    clientId: z.string().optional(),
    clientSecret: z.string().optional(),
    tokenExpiry: z.number().optional(),
  }),
  z.object({
    provider: z.literal("imap"),
    id: z.string(),
    name: z.string(),
    emailAddress: z.string(),
    imapHost: z.string(),
    imapPort: z.number(),
    username: z.string(),
    password: z.string(),
    tls: z.boolean(),
  }),
]);

export type EmailInboxConfig = z.infer<typeof EmailInboxConfigObject>;

const EmailIntegrationConfigObject = z.object({
  inboxes: z.array(EmailInboxConfigObject),
});

export type EmailIntegrationConfig = z.infer<
  typeof EmailIntegrationConfigObject
>;

const BurpSuiteIntegrationConfigObject = z.object({
  enabled: z.boolean(),
  transport: z.enum(["sse", "stdio"]).optional(),
  proxyUrl: z.string().optional(),
  sseUrl: z.string().optional(),
  mcpSseUrl: z.string().optional(),
  mcpProxyCommand: z.string().optional(),
  mcpProxyArgs: z.array(z.string()).optional(),
  timeoutMs: z.number().positive().optional(),
  allowedTargets: z.array(z.string()).optional(),
  allowConfigMutation: z.boolean().optional(),
  ignoreTlsErrors: z.boolean().optional(),
});

export type BurpSuiteIntegrationConfig = z.infer<
  typeof BurpSuiteIntegrationConfigObject
>;

const SessionConfigObject = z.object({
  offensiveHeaders: OffensiveHeadersConfigObject.optional(),
  sessionType: z.enum(["web-app"]).optional(),
  mode: z.enum(["auto", "driver", "operator"]).optional(),
  outcomeGuidance: z.string().optional(),
  scopeConstraints: ScopeConstraintsObject.optional(),
  authCredentials: z
    .union([AuthCredentialsObject, z.array(AuthCredentialsObject)])
    .optional(),
  authenticationInstructions: z.string().optional(),
  requestsPerSecond: z.number().optional(),
  operatorSettings: OperatorSettingsObject.optional(),
  /** Toolset state for controlling which tools are available */
  toolsetState: ToolsetStateSchema.optional(),
  /** Whether to enumerate subdomains during attack surface discovery (default: false) */
  enumerateSubdomains: z.boolean().optional(),
  /** Local codebase path for whitebox analysis (source code access) */
  codebasePath: z.string().optional(),
  /** Email inboxes available to the agent for monitoring/reading email */
  emailIntegration: EmailIntegrationConfigObject.optional(),
  /** Burp Suite pairing for proxy capture and MCP access */
  burpSuite: BurpSuiteIntegrationConfigObject.optional(),
  /** Enable exfiltration mode — allows internal pivoting and flag extraction through confirmed vulnerabilities */
  exfilMode: z.boolean().optional(),
  /** Agent working directory — resolved to process.cwd() by default, undefined in sandbox mode */
  agentCwd: z.string().optional(),
  /** Operator-provided guidance injected into the orchestrator/agent system prompts */
  prompt: z.string().optional(),
  /** Enable task-driven architecture — agents decompose objectives into tracked tasks (default: false) */
  taskDriven: z.boolean().optional(),
  /** When true, pentest agents run a plan phase before execution (default: false) */
  requirePlan: z.boolean().optional(),
});

export type SessionConfig = z.infer<typeof SessionConfigObject>;

// ============================================================================
// ExecutionSession - Legacy-compatible session interface for agent consumption
// ============================================================================

/**
 * Legacy-compatible session interface that provides directory paths
 * for agent artifact storage (findings, POCs, logs, etc.)
 *
 * This replaces the old core/agent/sessions module with safe Storage writes.
 */
export interface ExecutionSession {
  /** Unique session identifier (format: {prefix}-ses_{timestamp}_{random}) */
  id: string;
  /** Root path for all session artifacts (~/.pensar/sessions/{id}) */
  rootPath: string;
  /** Path for security findings (~/.pensar/sessions/{id}/findings) */
  findingsPath: string;
  /** Path for agent scratchpad notes (~/.pensar/sessions/{id}/scratchpad) */
  scratchpadPath: string;
  /** Path for execution logs (~/.pensar/sessions/{id}/logs) */
  logsPath: string;
  /** Path for proof-of-concept scripts (~/.pensar/sessions/{id}/pocs) */
  pocsPath: string;
  /** Target URL or system being tested */
  target: string;
  /** Testing objective description */
  objective: string;
  /** ISO timestamp when session was created */
  startTime: string;
  /** Session configuration */
  config?: SessionConfig;
}

/**
 * Input for creating an execution session
 */
export interface CreateExecutionInput {
  session: SessionInfo;
  /** Target URL or system to test */
  // target: string;
  // /** Testing objective description */
  // objective?: string;
  // /** Optional prefix for session ID (e.g., "benchmark-XBEN-001-24") */
  // prefix?: string;
  // /** Session configuration */
  // config?: SessionConfig;
}

/**
 * Get the base Pensar directory path
 */
export function getPensarDir(): string {
  return path.join(os.homedir(), ".pensar");
}

/**
 * Get the sessions directory path
 */
export function getSessionsDir(): string {
  return path.join(getPensarDir(), "sessions");
}

/**
 * Get the root path for a session's artifact directory
 */
export function getSessionRoot(id: string): string {
  return path.join(getSessionsDir(), id);
}

/**
 * Create a new session with directory structure for agent artifacts.
 * Uses Storage namespace for safe writes with locking.
 *
 * Directory structure created:
 * ~/.pensar/sessions/{id}/
 * ├── session.json      # Session metadata
 * ├── README.md         # Session documentation
 * ├── findings/         # Security findings
 * ├── scratchpad/       # Agent notes
 * ├── logs/             # Execution logs
 * └── pocs/             # Proof-of-concept scripts
 */
export async function createSessionDirs(
  input: CreateExecutionInput,
): Promise<void> {
  const { session } = input;

  // Create directory structure with locking
  await Storage.createDir(["sessions", session.id]);
  await Storage.createDir(["sessions", session.id, "findings"]);
  await Storage.createDir(["sessions", session.id, "scratchpad"]);
  await Storage.createDir(["sessions", session.id, "logs"]);
  await Storage.createDir(["sessions", session.id, "pocs"]);

  const startTime = new Date().toISOString();

  // Write README.md
  const readme = generateSessionReadme(session);
  await Storage.writeRaw(["sessions", session.id, "README.md"], readme);

  console.info("created session", session.id);
}

/**
 * Generate README.md content for a session
 */
function generateSessionReadme(session: SessionInfo): string {
  return `# Penetration Test Session

**Session ID:** ${session.id}
**Target:** ${session.targets}
**Objective:** ${session.config?.outcomeGuidance}
**Started:** ${session.time.created}

## Directory Structure

- \`findings/\` - Security findings and vulnerabilities
- \`scratchpad/\` - Notes and temporary data during testing
- \`logs/\` - Execution logs and command outputs
- \`pocs/\` - Proof-of-concept exploit scripts
- \`session.json\` - Session metadata

## Findings

Security findings will be documented in the \`findings/\` directory as individual files.

## Status

Testing in progress...
`;
}

/**
 * Get an execution session by ID
 */
export async function getExecution(
  sessionId: string,
): Promise<ExecutionSession | null> {
  try {
    const metadata = await Storage.read<
      ExecutionSession & {
        version: string;
        time: { created: number; updated: number };
      }
    >(["sessions", sessionId, "session"]);
    return metadata;
  } catch (e) {
    if (e instanceof Storage.NotFoundError) {
      return null;
    }
    throw e;
  }
}

/**
 * Resolve offensive headers based on session config
 */
export function getOffensiveHeaders(
  session: SessionInfo,
): Record<string, string> | undefined {
  const config = session.config?.offensiveHeaders;

  if (!config || config.mode === "none") {
    return undefined;
  }

  if (config.mode === "default") {
    return DEFAULT_OFFENSIVE_HEADERS;
  }

  if (config.mode === "custom" && config.headers) {
    return config.headers;
  }

  return undefined;
}

// ============================================================================
// SessionInfo - Original session metadata interface
// ============================================================================

export const SessionInfoObject = z.object({
  id: Identifier.schema("session"),
  name: z.string().optional(),
  version: z.string(),
  targets: z.array(z.string()),
  config: SessionConfigObject.optional(),
  time: z.object({
    created: z.number(),
    updated: z.number(),
  }),
  rootPath: z.string(),
  logsPath: z.string(),
  findingsPath: z.string(),
  scratchpadPath: z.string(),
  pocsPath: z.string(),
});

export type SessionInfo = z.output<typeof SessionInfoObject> & {
  _rateLimiter?: RateLimiter;
  credentialManager?: CredentialManager;
  tokensIn?: number;
  tokensOut?: number;
};

export interface CreateInputProps {
  id?: string;
  targets: string[];
  /** Explicit session name. When omitted, an AI-generated name is attempted
   *  (requires `model` + `authConfig`), falling back to a random name. */
  name?: string;
  prefix?: string;
  config?: SessionConfig;
  /** AI model for session name generation (optional). */
  model?: AIModel;
  /** Auth config for the AI provider (optional). */
  authConfig?: AIAuthConfig;
  /** User objective / first prompt — used as context for AI name generation. */
  userMessage?: string;
  /** Called when the async AI name generation resolves with a name. */
  onNameGenerated?: (name: string) => void;
}

export async function create(input: CreateInputProps) {
  const name = input.name ?? generateRandomName();

  const id =
    `${input.prefix ? input.prefix : ""}` +
    Identifier.descending("session", input.id);

  const rootPath = getSessionRoot(id);
  const findingsPath = path.join(rootPath, "findings");
  const scratchpadPath = path.join(rootPath, "scratchpad");
  const logsPath = path.join(rootPath, "logs");
  const pocsPath = path.join(rootPath, "pocs");

  const rateLimiter = new RateLimiter({
    requestsPerSecond: input.config?.requestsPerSecond,
  });

  // Auto-create CredentialManager when authCredentials are provided.
  // Secrets live only in memory — they are never serialized to disk.
  let credentialManager: CredentialManager | undefined;
  if (input.config?.authCredentials) {
    credentialManager = new CredentialManager();
    const creds = Array.isArray(input.config.authCredentials)
      ? input.config.authCredentials
      : [input.config.authCredentials];
    for (const cred of creds) {
      credentialManager.addFromAuthCredentials(cred);
    }
  }

  const result: SessionInfo = {
    id: id,
    version: getCurrentVersion(),
    targets: input.targets,
    name,
    time: {
      created: Date.now(),
      updated: Date.now(),
    },
    config: {
      ...input.config,
      mode: input.config?.mode || "auto",
      offensiveHeaders: input.config?.offensiveHeaders || {
        mode: "default",
        headers: {
          "User-Agent": "pensar-apex",
        },
      },
      outcomeGuidance:
        input.config?.outcomeGuidance ||
        (input.config?.exfilMode
          ? EXFIL_OUTCOME_GUIDANCE
          : DEFAULT_OUTCOME_GUIDANCE),
    },
    _rateLimiter: rateLimiter,
    credentialManager,
    rootPath,
    logsPath,
    pocsPath,
    scratchpadPath,
    findingsPath,
  };

  console.info("created session", result);

  // Exclude non-serializable fields (class instances with methods)
  const { _rateLimiter, credentialManager: _cm, ...sessionData } = result;
  await createSessionDirs({ session: result });
  await Storage.write(["sessions", result.id, "session"], sessionData);

  // Fire-and-forget AI name generation — updates persisted session in the background
  if (!input.name && input.model) {
    generateSessionName({
      targets: input.targets,
      userMessage: input.userMessage,
      model: input.model,
      authConfig: input.authConfig,
    }).then((aiName) => {
      if (aiName) {
        result.name = aiName;
        update(result.id, (s) => {
          s.name = aiName;
        }).catch(() => {});
        input.onNameGenerated?.(aiName);
      }
    });
  }

  return result;
}

export const get = async (id: string) => {
  const read = await Storage.read<SessionInfo>(["sessions", id, "session"]);

  // Reconstruct RateLimiter instance (it gets serialized as plain object)
  // This ensures the session has a proper RateLimiter with methods
  if (read.config?.requestsPerSecond) {
    read._rateLimiter = new RateLimiter({
      requestsPerSecond: read.config.requestsPerSecond,
    });
  } else {
    // Remove any stale serialized _rateLimiter data (plain object without methods)
    delete read._rateLimiter;
  }

  return read;
};

export const sessionPath = (id: string) => Storage.locate(["sessions", id], "");

export async function update(
  id: string,
  editor: (session: SessionInfo) => void,
) {
  const result = await Storage.update<SessionInfo>(
    ["sessions", id, "session"],
    (draft) => {
      editor(draft);
      draft.time.updated = Date.now();
    },
  );
  console.info("updated session", result);
  return result;
}

export async function* list() {
  const sessionsDir = getSessionsDir();
  let entries: import("fs").Dirent[];
  try {
    entries = await import("fs/promises").then((fsp) =>
      fsp.readdir(sessionsDir, { withFileTypes: true }),
    );
  } catch {
    return;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    try {
      yield await Storage.read<SessionInfo>([
        "sessions",
        entry.name,
        "session",
      ]);
    } catch {
      // Skip directories without a valid session.json
    }
  }
}

const RemoveInput = z.object({
  sessionId: Identifier.schema("session"),
});

export const remove = async (input: z.output<typeof RemoveInput>) => {
  try {
    // Remove the entire session directory (metadata + artifacts)
    const sessionDir = getSessionRoot(input.sessionId);
    const fsp = await import("fs/promises");
    await fsp.rm(sessionDir, { recursive: true, force: true });
  } catch (e) {
    console.error(e);
  }
};

export const updateMessage = async (msg: Message) => {
  await Storage.write(["sessions", msg.sessionId, "messages", msg.id], msg);
  return msg;
};

const RemoveMsgInput = z.object({
  sessionId: Identifier.schema("session"),
  messageId: Identifier.schema("message"),
});

export const removeMessage = async (input: z.output<typeof RemoveMsgInput>) => {
  await Storage.remove([
    "sessions",
    input.sessionId,
    "messages",
    input.messageId,
  ]);
  return input.messageId;
};

// ============================================================================
// Operator Session State - For resume functionality
// ============================================================================

/**
 * Persisted operator dashboard state for session resumption.
 *
 * `messages` stores raw AI SDK model messages (the single source of truth).
 * Display messages are derived on resume via `convertModelMessagesToUI`.
 *
 * Note: The runtime operator state type lives in `operator/types.ts` as
 * `OperatorSessionState` — this is the persistence shape only.
 */
export interface PersistedOperatorState {
  /** Operator mode: plan, manual, auto */
  mode: string;
  /** Whether commands require user approval before execution */
  requireApproval: boolean;
  /** Current stage: setup, recon, foothold, etc. */
  currentStage: string;
  /** Raw AI SDK model messages — single source of truth for conversation history */
  messages: ModelMessage[];
  /** Discovered attack surface endpoints */
  attackSurface: unknown[];
  /** Found credentials */
  credentials: unknown[];
  /** Verified vulnerabilities */
  verifiedVulns: unknown[];
  /** Target state (host, phase, objective) */
  targetState: unknown;
  /** Tracked hypotheses */
  hypotheses: unknown[];
  /** Collected evidence */
  evidence: unknown[];
  /** Action approval history */
  actionHistory: unknown[];
  /** When the session was paused */
  pausedAt: string;
  /** Last run ID for log correlation */
  lastRunId: string;
}

/**
 * Load operator dashboard state for session resumption.
 *
 * The agent persists a plain `ModelMessage[]` array to `messages.json`,
 * so we normalise that into a `PersistedOperatorState` envelope here.
 */
export async function loadOperatorState(
  sessionId: string,
): Promise<PersistedOperatorState | null> {
  try {
    const session = await get(sessionId);
    const statePath = path.join(session.rootPath, "messages.json");
    if (!existsSync(statePath)) return null;
    const data = readFileSync(statePath, "utf-8");
    const parsed = JSON.parse(data);

    // The agent writes a raw ModelMessage[] array — wrap it.
    if (Array.isArray(parsed)) {
      return {
        mode: session.config?.operatorSettings?.initialMode ?? "manual",
        requireApproval:
          session.config?.operatorSettings?.requireApproval ?? true,
        currentStage: "recon",
        messages: parsed as ModelMessage[],
        attackSurface: [],
        credentials: [],
        verifiedVulns: [],
        targetState: null,
        hypotheses: [],
        evidence: [],
        actionHistory: [],
        pausedAt: new Date().toISOString(),
        lastRunId: "",
      };
    }

    return parsed as PersistedOperatorState;
  } catch (error) {
    console.error("Error loading operator state:", error);
    return null;
  }
}

/**
 * Check if a session has saved operator state
 */
export function hasOperatorState(session: SessionInfo): boolean {
  const statePath = path.join(session.rootPath, "messages.json");
  return existsSync(statePath);
}

/**
 * Maximum number of model messages to pass to the AI when resuming a session.
 *
 * Keeps enough context for the agent to continue effectively without hitting
 * the model's context window and triggering an immediate summarization cycle.
 * The value is conservative; tool-heavy conversations can produce many messages
 * per logical "turn" (assistant → tool × N), so 200 messages ≈ 20–50 turns.
 */
const MAX_RESUME_MESSAGES = 200;

/**
 * Return the tail subset of model messages suitable for resuming an agent.
 *
 * The full message array may be very long after an extended session. Feeding
 * it all back to the model on resume would immediately exceed the context
 * window and force an expensive summarization pass. Instead we keep only the
 * most recent messages, cutting at a clean "user" message boundary so that no
 * tool-call / tool-result pairs are orphaned.
 */
export function getResumeMessages(
  messages: ModelMessage[],
  limit: number = MAX_RESUME_MESSAGES,
): ModelMessage[] {
  if (messages.length <= limit) return messages;

  // Walk backward from `limit` positions before the end to find the nearest
  // "user" message — that is a safe boundary because every tool-call /
  // tool-result exchange that follows it will be complete.
  let cutIndex = messages.length - limit;

  // Search forward from the rough cut point for the next user message.
  // This guarantees we don't start mid-turn (e.g. on an orphaned tool
  // result whose assistant tool-call was trimmed).
  while (cutIndex < messages.length) {
    if (messages[cutIndex].role === "user") break;
    cutIndex++;
  }

  // If we couldn't find a user message (unlikely), fall back to the raw cut.
  if (cutIndex >= messages.length) {
    cutIndex = messages.length - limit;
  }

  return messages.slice(cutIndex);
}

/**
 * Sanitize a model-message array so it conforms to the ModelMessage[] schema
 * required by the AI SDK.
 *
 * Specifically this:
 *  1. Merges consecutive `user` messages into a single message (joins with
 *     newlines) so the conversation never has back-to-back user turns.
 *  2. Fixes tool-result `output` fields that are raw strings — the AI SDK's
 *     `outputSchema` requires a discriminated-union object like
 *     `{ type: "text", value: "..." }`.  Raw strings were produced by older
 *     abort-recovery code and cause "The messages do not match the
 *     ModelMessage[] schema" errors on resume.
 *
 * This is intentionally a best-effort safety-net.
 */
export function normalizeMessages(messages: ModelMessage[]): ModelMessage[] {
  if (messages.length <= 1) return fixToolOutputs(messages);

  const result: ModelMessage[] = [];

  for (const msg of messages) {
    const prev = result[result.length - 1];

    if (
      prev &&
      prev.role === "user" &&
      msg.role === "user" &&
      typeof prev.content === "string" &&
      typeof msg.content === "string"
    ) {
      // Merge consecutive user messages
      result[result.length - 1] = {
        ...prev,
        content: `${prev.content}\n\n${msg.content}`,
      };
    } else if (prev && prev.role === "user" && msg.role === "user") {
      // One or both have structured content — replace with the latest
      result[result.length - 1] = msg;
    } else {
      result.push(msg);
    }
  }

  return fixToolOutputs(result);
}

/**
 * Walk through messages and upgrade any tool-result parts whose `output` is a
 * raw string to the structured `{ type: "text", value: string }` format
 * expected by the AI SDK v6 `outputSchema`.
 */
function fixToolOutputs(messages: ModelMessage[]): ModelMessage[] {
  let changed = false;

  const fixed = messages.map((msg) => {
    if (msg.role !== "tool" || !Array.isArray(msg.content)) return msg;

    let partChanged = false;
    const fixedContent = (msg.content as Array<Record<string, unknown>>).map(
      (part) => {
        if (part.type === "tool-result" && typeof part.output === "string") {
          partChanged = true;
          return { ...part, output: { type: "text", value: part.output } };
        }
        return part;
      },
    );

    if (partChanged) {
      changed = true;
      return { ...msg, content: fixedContent } as ModelMessage;
    }
    return msg;
  });

  return changed ? fixed : messages;
}

// ============================================================================
// Runtime Operator Settings Update
// ============================================================================

/**
 * Update operator settings for a running session
 * This persists the changes to the session config
 */
export async function updateOperatorSettings(
  sessionId: string,
  settings: Partial<OperatorSettings>,
): Promise<SessionInfo> {
  return await update(sessionId, (session) => {
    if (!session.config) {
      session.config = {};
    }
    if (!session.config.operatorSettings) {
      session.config.operatorSettings = {
        initialMode: "manual",
        requireApproval: true,
        enableSuggestions: true,
      };
    }

    // Update only the provided settings
    if (settings.initialMode !== undefined) {
      session.config.operatorSettings.initialMode = settings.initialMode;
    }
    if (settings.requireApproval !== undefined) {
      session.config.operatorSettings.requireApproval =
        settings.requireApproval;
    }
    if (settings.enableSuggestions !== undefined) {
      session.config.operatorSettings.enableSuggestions =
        settings.enableSuggestions;
    }
  });
}

// ============================================================================
// Toolset State Management
// ============================================================================

/**
 * Update the toolset state for a session
 */
export async function updateToolsetState(
  sessionId: string,
  toolsetState: ToolsetState,
): Promise<SessionInfo> {
  return await update(sessionId, (session) => {
    if (!session.config) {
      session.config = {};
    }
    session.config.toolsetState = toolsetState;
  });
}

/**
 * Toggle a specific tool's enabled state
 */
export async function toggleTool(
  sessionId: string,
  toolId: string,
  enabled: boolean,
): Promise<SessionInfo> {
  return await update(sessionId, (session) => {
    if (!session.config) {
      session.config = {};
    }
    if (!session.config.toolsetState) {
      // Initialize with all tools enabled if no state exists
      const { createToolsetState } = require("../toolset");
      session.config.toolsetState = createToolsetState("web-pentest");
    }
    session.config.toolsetState = toolsetToggle(
      session.config.toolsetState!,
      toolId,
      enabled,
    );
  });
}

export const sessions = {
  getSessionRoot,
  getOffensiveHeaders,
  DEFAULT_OUTCOME_GUIDANCE,
  EXFIL_OUTCOME_GUIDANCE,
  create,
  get,
  update,
  list,
  remove,
  updateMessage,
  removeMessage,
  loadOperatorState,
  hasOperatorState,
  getResumeMessages,
  updateOperatorSettings,
  updateToolsetState,
  toggleTool,
};
