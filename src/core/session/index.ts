import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { ModelMessage } from "ai";
import z from "zod";
import { generateRandomName, generateSessionName } from "../../util/name";
import type { AIAuthConfig, AIModel } from "../ai";
import { CredentialManager } from "../credentials";
import * as Identifier from "../id/id";
import { getCurrentVersion } from "../installation";
import type { Message } from "../messages/types";
import { RateLimiter } from "../services/rateLimiter";
import * as Storage from "../storage";
import {
  type ToolsetState,
  ToolsetStateSchema,
  toggleTool as toolsetToggle,
} from "../toolset";

/**
 * Default outcome guidance (safe, non-destructive)
 */
const DEFAULT_OUTCOME_GUIDANCE =
  "Prove the exploit can be run but do not exfiltrate data or cause any harm to the system. " +
  "Create proof-of-concept exploits that demonstrate the vulnerability exists without causing damage.";

/**
 * Exfil-mode outcome guidance (extract flags / sensitive data)
 */
export const EXFIL_OUTCOME_GUIDANCE =
  "Exfiltrate data to extract the flag value. " +
  "Create proof-of-concept exploits that successfully extract the flag from the target system.";

// Fallback when neither the caller nor global config supplies headers.
const DEFAULT_HEADER_RECORD: Record<string, string> = {
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

type ScopeConstraints = z.infer<typeof ScopeConstraintsObject>;

const NetworkSecurityConfigObject = z.object({
  /** `strict` requires externally-attested default-deny process egress. */
  egress: z.enum(["unrestricted", "strict"]).optional(),
  /** Permit DNS through a controller-owned resolver. Defaults to true. */
  allowDns: z.boolean().optional(),
  /** Allocate an opaque session callback route and reserved listener port. */
  oast: z
    .object({
      enabled: z.boolean().default(true),
      callbackPort: z.number().int().min(1024).max(65535).default(4000),
    })
    .optional(),
});

export type NetworkSecurityConfig = z.infer<typeof NetworkSecurityConfigObject>;

const ContextCompactionConfigObject = z.object({
  enabled: z.boolean().optional(),
  model: z.string().min(1).optional(),
  thresholdRatio: z.number().min(0.5).max(0.95).optional(),
  reasoning: z.enum(["off", "low", "medium", "high"]).optional(),
});

// The header map IS the state — empty record means "send no custom headers".
const SessionHeadersRecord = z.record(z.string(), z.string());

// Legacy shape kept only so downstream `pensarai/console` agents keep
// typechecking. Normalized into `headers` at every input boundary and
// stripped before persistence.
const OffensiveHeadersConfigObject = z.object({
  mode: z.enum(["none", "default", "custom"]).optional(),
  headers: SessionHeadersRecord.optional(),
});

/** @deprecated Pass flat `SessionConfig.headers: Record<string, string>` directly. */
export type OffensiveHeadersConfig = z.infer<
  typeof OffensiveHeadersConfigObject
>;

const OperatorSettingsObject = z.object({
  initialMode: z.enum(["plan", "manual", "auto"]).default("manual"),
  requireApproval: z.boolean().default(true),
  enableSuggestions: z.boolean().default(true),
  /** Run the top-level operator as a focused solo researcher without orchestration tools. */
  strikeMode: z.boolean().optional(),
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
  z.object({
    provider: z.literal("http"),
    id: z.string(),
    name: z.string(),
    emailAddress: z.string(),
    endpoint: z.string(),
    token: z.string(),
  }),
]);

export type EmailInboxConfig = z.infer<typeof EmailInboxConfigObject>;

const EmailIntegrationConfigObject = z.object({
  inboxes: z.array(EmailInboxConfigObject),
});

export type EmailIntegrationConfig = z.infer<
  typeof EmailIntegrationConfigObject
>;

const SmtpConfigObject = z.object({
  host: z.string(),
  port: z.number(),
  username: z.string(),
  password: z.string(),
  tls: z.boolean().default(true),
  fromAddress: z.string().optional(),
});

export type SmtpConfig = z.infer<typeof SmtpConfigObject>;

/**
 * Resolve SMTP config from environment variables when not explicitly provided.
 *
 * - `RESEND_API_KEY` → Resend SMTP (smtp.resend.com:465, user "resend")
 * - `SMTP_HOST` + `SMTP_PORT` + `SMTP_USERNAME` + `SMTP_PASSWORD` → generic SMTP
 * - `OUTBOUND_EMAIL` → fromAddress for either path
 */
function resolveSmtpConfig(explicit?: SmtpConfig): SmtpConfig | undefined {
  if (explicit) return explicit;

  const fromAddress = process.env.OUTBOUND_EMAIL;

  const resendKey = process.env.RESEND_API_KEY;
  if (resendKey) {
    return {
      host: "smtp.resend.com",
      port: 465,
      username: "resend",
      password: resendKey,
      tls: true,
      fromAddress,
    };
  }

  const host = process.env.SMTP_HOST;
  const port = process.env.SMTP_PORT;
  const username = process.env.SMTP_USERNAME;
  const password = process.env.SMTP_PASSWORD;
  if (host && port && username && password) {
    return {
      host,
      port: parseInt(port, 10),
      username,
      password,
      tls: process.env.SMTP_TLS !== "false",
      fromAddress,
    };
  }

  return undefined;
}

const SessionConfigObject = z.object({
  /**
   * Custom HTTP headers for outbound target requests. Snapshotted from
   * `config.defaultHeaders` at create time; read via the resolver in
   * `src/core/http/targetHeaders.ts`, not directly by tools.
   */
  headers: SessionHeadersRecord.optional(),
  /** @deprecated Pass flat `headers` instead. Normalized at input boundaries. */
  offensiveHeaders: OffensiveHeadersConfigObject.optional(),
  sessionType: z.enum(["web-app"]).optional(),
  mode: z.enum(["auto", "driver", "operator"]).optional(),
  outcomeGuidance: z.string().optional(),
  scopeConstraints: ScopeConstraintsObject.optional(),
  /** Sandbox control-plane policy. Strict mode fails closed without attestation. */
  networkSecurity: NetworkSecurityConfigObject.optional(),
  /** Provider-neutral continuation capsules. Enabled by default. */
  contextCompaction: ContextCompactionConfigObject.optional(),
  authCredentials: z
    .union([AuthCredentialsObject, z.array(AuthCredentialsObject)])
    .optional(),
  authenticationInstructions: z.string().optional(),
  requestsPerSecond: z.number().positive().max(1000).optional(),
  /**
   * Opt-in: the client has authorized destructive testing (DB deletes/drops,
   * API write-deletes, catastrophic host operations). Defaults to off — when
   * absent or false, the destructive-action guard blocks those operations at
   * the `http_request` / `execute_command` tool boundary. See
   * `agents/offSecAgent/tools/destructiveGuard.ts`.
   */
  allowDestructiveActions: z.boolean().optional(),
  /**
   * Opt-in: the client has authorized rate-limit / anti-automation / volumetric
   * (light-DoS) testing — request bursts to probe for missing throttling.
   * Defaults to off — when absent or false, the pentest system prompt tells the
   * agent that burst/volumetric testing is out of scope. Independent of this
   * flag, endpoints with real-world side effects (email/SMS, notifications,
   * contact forms, payments) are never looped — see the side-effect safety
   * section in `agents/specialized/pentest/agent.ts`.
   */
  allowRateLimitTesting: z.boolean().optional(),
  operatorSettings: OperatorSettingsObject.optional(),
  /** Toolset state for controlling which tools are available */
  toolsetState: ToolsetStateSchema.optional(),
  /** Whether to enumerate subdomains during attack surface discovery (default: false) */
  enumerateSubdomains: z.boolean().optional(),
  /** Local codebase path for whitebox analysis (source code access) */
  codebasePath: z.string().optional(),
  /** Email inboxes available to the agent for monitoring/reading email */
  emailIntegration: EmailIntegrationConfigObject.optional(),
  /** SMTP config for outbound email (direct SMTP or Resend via SMTP) */
  smtpConfig: SmtpConfigObject.optional(),
  /** Enable exfiltration mode — allows internal pivoting and flag extraction through confirmed vulnerabilities */
  exfilMode: z.boolean().optional(),
  /** Allow bounded correction when Fast Strike claims impact without proof. */
  requireSuccessfulResponse: z.boolean().optional(),
  /** Explicit benchmark-only competitive lane count. Production defaults to one. */
  fastStrikeLanes: z.number().int().min(1).max(3).optional(),
  /** Deadline for each explicitly enabled competitive lane. */
  fastStrikeLaneTimeoutMs: z
    .number()
    .int()
    .min(60_000)
    .max(3_600_000)
    .optional(),
  /** Use one durable scan-level lead over the complete discovered surface. */
  engagementLead: z.boolean().optional(),
  /** Agent working directory — resolved to process.cwd() by default, undefined in sandbox mode */
  agentCwd: z.string().optional(),
  /** Operator-provided guidance injected into the orchestrator/agent system prompts */
  prompt: z.string().optional(),
  /** Enable task-driven architecture — agents decompose objectives into tracked tasks (default: false) */
  taskDriven: z.boolean().optional(),
  /** When true, pentest agents run a plan phase before execution (default: false) */
  requirePlan: z.boolean().optional(),
  /**
   * Opt-out: disable sub-agent orchestration for targeted pentests. When true,
   * the per-target pentest agent runs SOLO as a single worker — it tests every
   * objective itself instead of acting as an orchestrator that spawns one
   * `spawn_pentest_agent` worker per objective. Removes the `spawn_pentest_agent`
   * tool and swaps the orchestrator system prompt for the worker prompt. Defaults
   * to off (orchestrated fan-out). Trades depth for lower cost and duration — the
   * orchestrated path is more thorough but spends a full agent run per objective.
   */
  disableSubagents: z.boolean().optional(),
  /** Local filesystem path for prompt-injection payload library */
  promptInjectionLibrarySource: z.string().optional(),
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
interface ExecutionSession {
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
function getPensarDir(): string {
  return path.join(os.homedir(), ".pensar");
}

/**
 * Get the sessions directory path
 */
function getSessionsDir(): string {
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
async function createSessionDirs(input: CreateExecutionInput): Promise<void> {
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
async function getExecution(
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

// Translate the deprecated `offensiveHeaders: { mode, headers? }` into
// flat `headers` and strip the legacy field. Pure / non-mutating.
//
// Precedence: flat `headers` wins if present; mode "default" seeds the
// default record; mode "none" yields `{}` (must override `oh.headers`).
function normalizeDeprecatedHeaders<T extends { offensiveHeaders?: unknown }>(
  config: T | undefined,
): Omit<T, "offensiveHeaders"> | undefined {
  if (!config) return config;
  if (config.offensiveHeaders == null) {
    const { offensiveHeaders: _drop, ...rest } = config;
    return rest;
  }
  const { offensiveHeaders, ...rest } = config;
  const restWithHeaders = rest as Omit<T, "offensiveHeaders"> & {
    headers?: Record<string, string>;
  };
  if (restWithHeaders.headers !== undefined) {
    return restWithHeaders;
  }
  const oh = offensiveHeaders as {
    mode?: string;
    headers?: Record<string, string>;
  };
  if (oh.mode === "none") {
    return { ...restWithHeaders, headers: {} };
  }
  let headers: Record<string, string> = {};
  if (oh.mode === "default") headers = { ...DEFAULT_HEADER_RECORD };
  if (oh.headers) headers = { ...headers, ...oh.headers };
  return { ...restWithHeaders, headers };
}

// Migrate a legacy session.json into the flat-headers shape. The on-disk
// file is only rewritten on the next save.
export function migrateLegacySessionData(input: unknown): unknown {
  if (!input || typeof input !== "object") return input;
  const root = input as Record<string, unknown>;
  const config = root.config;
  if (!config || typeof config !== "object") return input;
  const cfg = config as Record<string, unknown>;
  if (!("offensiveHeaders" in cfg)) return input;
  return { ...root, config: normalizeDeprecatedHeaders(cfg) };
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

  // Internal code only sees flat `headers` from here on.
  const normalizedConfig = normalizeDeprecatedHeaders(input.config) as
    | SessionConfig
    | undefined;

  const id =
    `${input.prefix ? input.prefix : ""}` +
    Identifier.descending("session", input.id);

  const rootPath = getSessionRoot(id);
  const findingsPath = path.join(rootPath, "findings");
  const scratchpadPath = path.join(rootPath, "scratchpad");
  const logsPath = path.join(rootPath, "logs");
  const pocsPath = path.join(rootPath, "pocs");

  const requestsPerSecond = Math.min(
    1000,
    Math.max(1, Math.round(normalizedConfig?.requestsPerSecond ?? 50)),
  );
  const rateTestingAllowed = normalizedConfig?.allowRateLimitTesting === true;
  const rateLimiter = new RateLimiter({
    requestsPerSecond,
    burst: rateTestingAllowed ? requestsPerSecond : 1,
    maxConcurrency: rateTestingAllowed
      ? Math.min(requestsPerSecond, 32)
      : Math.min(requestsPerSecond, 4),
  });

  // Auto-create CredentialManager when authCredentials are provided.
  // Secrets live only in memory — they are never serialized to disk.
  let credentialManager: CredentialManager | undefined;
  if (normalizedConfig?.authCredentials) {
    credentialManager = new CredentialManager();
    const creds = Array.isArray(normalizedConfig.authCredentials)
      ? normalizedConfig.authCredentials
      : [normalizedConfig.authCredentials];
    for (const cred of creds) {
      credentialManager.addFromAuthCredentials(cred);
    }
  }

  const smtpConfig = resolveSmtpConfig(normalizedConfig?.smtpConfig);

  // Caller `headers` wins verbatim; otherwise snapshot the current global
  // defaultHeaders so the session is locked at create time.
  const { config: appConfig } = await import("../config");
  const globalConfig = await appConfig.get();
  let snapshotHeaders: Record<string, string>;
  if (normalizedConfig?.headers !== undefined) {
    snapshotHeaders = { ...normalizedConfig.headers };
  } else {
    snapshotHeaders = globalConfig.defaultHeaders
      ? { ...globalConfig.defaultHeaders }
      : { ...DEFAULT_HEADER_RECORD };
  }

  const contextCompaction = normalizedConfig?.contextCompaction ?? {
    enabled: globalConfig.contextCompactionEnabled ?? true,
    model: globalConfig.contextCompactionModel ?? undefined,
    thresholdRatio: globalConfig.contextCompactionThresholdRatio ?? 0.7,
  };

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
      ...normalizedConfig,
      mode: normalizedConfig?.mode || "auto",
      headers: snapshotHeaders,
      contextCompaction,
      outcomeGuidance:
        normalizedConfig?.outcomeGuidance ||
        (normalizedConfig?.exfilMode
          ? EXFIL_OUTCOME_GUIDANCE
          : DEFAULT_OUTCOME_GUIDANCE),
      smtpConfig,
    },
    _rateLimiter: rateLimiter,
    credentialManager,
    rootPath,
    logsPath,
    pocsPath,
    scratchpadPath,
    findingsPath,
  };

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
  const raw = await Storage.read<unknown>(["sessions", id, "session"]);
  const read = migrateLegacySessionData(raw) as SessionInfo;

  // Reconstruct RateLimiter instance (it gets serialized as plain object)
  // This ensures the session has a proper RateLimiter with methods
  if (read.config) {
    const requestsPerSecond = Math.min(
      1000,
      Math.max(1, Math.round(read.config.requestsPerSecond ?? 50)),
    );
    const rateTestingAllowed = read.config.allowRateLimitTesting === true;
    read._rateLimiter = new RateLimiter({
      requestsPerSecond,
      burst: rateTestingAllowed ? requestsPerSecond : 1,
      maxConcurrency: rateTestingAllowed
        ? Math.min(requestsPerSecond, 32)
        : Math.min(requestsPerSecond, 4),
    });
  } else {
    // Remove any stale serialized _rateLimiter data (plain object without methods)
    delete read._rateLimiter;
  }

  return read;
};

const sessionPath = (id: string) => Storage.locate(["sessions", id], "");

async function update(id: string, editor: (session: SessionInfo) => void) {
  const result = await Storage.update<SessionInfo>(
    ["sessions", id, "session"],
    (draft) => {
      editor(draft);
      draft.time.updated = Date.now();
    },
  );
  return result;
}

export async function* list() {
  const sessionsDir = getSessionsDir();
  let entries: import("fs").Dirent[];
  try {
    entries = await import("node:fs/promises").then((fsp) =>
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

const remove = async (input: z.output<typeof RemoveInput>) => {
  try {
    // Remove the entire session directory (metadata + artifacts)
    const sessionDir = getSessionRoot(input.sessionId);
    const fsp = await import("node:fs/promises");
    await fsp.rm(sessionDir, { recursive: true, force: true });
  } catch (e) {
    console.error(e);
  }
};

const updateMessage = async (msg: Message) => {
  await Storage.write(["sessions", msg.sessionId, "messages", msg.id], msg);
  return msg;
};

const RemoveMsgInput = z.object({
  sessionId: Identifier.schema("session"),
  messageId: Identifier.schema("message"),
});

const removeMessage = async (input: z.output<typeof RemoveMsgInput>) => {
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
 * Target number of model messages to pass to the AI when resuming a session.
 *
 * Keeps enough context for the agent to continue effectively without hitting
 * the model's context window and triggering an immediate summarization cycle.
 * This is a replay-size target, not a token or turn budget. A single tool-heavy
 * turn can exceed it.
 */
const RESUME_MESSAGE_WINDOW = 200;

/**
 * Return the tail subset of model messages suitable for resuming an agent.
 *
 * The full message array may be very long after an extended session. Feeding
 * it all back to the model on resume would immediately exceed the context
 * window and force an expensive summarization pass. Instead we prefer the most
 * recent messages, cutting at a clean "user" message boundary so that no
 * tool-call / tool-result pairs are orphaned. When the latest turn is larger
 * than the target window, preserving the complete turn takes precedence.
 */
export function getResumeMessages(
  messages: ModelMessage[],
  limit: number = RESUME_MESSAGE_WINDOW,
): ModelMessage[] {
  if (messages.length <= limit) return messages;

  const roughCutIndex = messages.length - limit;
  let cutIndex = roughCutIndex;

  // Search forward from the rough cut point for the next user message.
  // This guarantees we don't start mid-turn (e.g. on an orphaned tool
  // result whose assistant tool-call was trimmed).
  while (cutIndex < messages.length) {
    if (messages[cutIndex].role === "user") break;
    cutIndex++;
  }

  // A single autonomous turn can exceed the target window. In that case,
  // include the preceding user message rather than splitting the turn.
  if (cutIndex >= messages.length) {
    cutIndex = roughCutIndex;
    while (cutIndex > 0 && messages[cutIndex].role !== "user") {
      cutIndex--;
    }
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
        strikeMode: false,
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
    if (settings.strikeMode !== undefined) {
      session.config.operatorSettings.strikeMode = settings.strikeMode;
    }
  });
}

// ============================================================================
// Custom HTTP Headers Update
// ============================================================================

/** Replace the session's custom HTTP headers. Pass `{}` to clear. */
export async function updateSessionHeaders(
  sessionId: string,
  headers: Record<string, string>,
): Promise<SessionInfo> {
  return await update(sessionId, (session) => {
    if (!session.config) {
      session.config = {};
    }
    session.config.headers = { ...headers };
  });
}

// ============================================================================
// Toolset State Management
// ============================================================================

/**
 * Update the toolset state for a session
 */
async function updateToolsetState(
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
async function toggleTool(
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
  EXFIL_OUTCOME_GUIDANCE,
  create,
  get,
  remove,
  loadOperatorState,
  hasOperatorState,
  getResumeMessages,
  updateOperatorSettings,
  updateSessionHeaders,
};
