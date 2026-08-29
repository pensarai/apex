import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { getCurrentVersion } from "../installation";

const DEFAULT_CONFIG: Config = {
  responsibleUseAccepted: false,
  defaultHeaders: { "User-Agent": "pensar-apex" },
  strikeMode: false,
};

export interface Config {
  version?: string;
  openAiAPIKey?: string | null;
  anthropicAPIKey?: string | null;
  googleAPIKey?: string | null;
  openRouterAPIKey?: string | null;
  concentrateAPIKey?: string | null;
  inceptionAPIKey?: string | null;
  bedrockAPIKey?: string | null;
  pensarAPIKey?: string | null;
  responsibleUseAccepted: boolean;
  // Remote execution providers
  daytonaAPIKey?: string | null;
  daytonaOrgId?: string | null;
  runloopAPIKey?: string | null;
  // Direct search
  braveAPIKey?: string | null;
  // Local LLM
  localModelUrl?: string | null;
  localModelName?: string | null;
  // Theme preferences
  theme?: string;
  themeMode?: "dark" | "light" | "auto";
  // Use the terminal's default background so a transparent terminal shows through.
  transparentBackground?: boolean;
  // Model preference
  selectedModelId?: string | null;
  /** Optional dedicated provider/model id for context compaction. */
  contextCompactionModel?: string | null;
  /** Defaults to true. Set PENSAR_CONTEXT_COMPACTION=legacy for the old summarizer. */
  contextCompactionEnabled?: boolean;
  contextCompactionThresholdRatio?: number;
  recentModelIds?: string[];
  // Extended thinking / reasoning
  reasoningEnabled?: boolean;
  openAIReasoningEffort?:
    | "none"
    | "low"
    | "medium"
    | "high"
    | "xhigh"
    | "max"
    | "ultra"
    | null;
  // Default workflow for newly created TUI operator sessions.
  strikeMode?: boolean;
  // Whitebox attack surface: when false, skip the @pensar/surface deterministic
  // enumeration path and use the legacy pages+apiEndpoints discovery agents.
  // Defaults to true when unset.
  surfaceIntegrationEnabled?: boolean;
  // WorkOS CLI auth (replaces pensarAPIKey for new auth flow)
  accessToken?: string | null;
  refreshToken?: string | null;
  workspaceId?: string | null;
  workspaceSlug?: string | null;
  // Gateway request signing key (server-issued)
  gatewaySigningKey?: string | null;
  // Gateway URL for inference (server-issued, bypasses CloudFront timeout)
  gatewayUrl?: string | null;
  /** Snapshotted into every new session at create time. */
  defaultHeaders?: Record<string, string>;
  defaultHeadersUpdatedAt?: string;
}

export async function init() {
  const folder = path.join(os.homedir(), ".pensar");
  const file = path.join(folder, "config.json");
  const dirExists = await fs
    .access(folder)
    .then(() => true)
    .catch(() => false);
  if (!dirExists) {
    await fs.mkdir(folder, { recursive: true });
  }
  const fileExists = await fs
    .access(file)
    .then(() => true)
    .catch(() => false);
  if (!fileExists) {
    await fs.writeFile(file, JSON.stringify(DEFAULT_CONFIG));
  }

  const version = getCurrentVersion();
  return { ...DEFAULT_CONFIG, version };
}

/**
 * Parse a truthy/falsy env value. Returns undefined when unset so callers can
 * fall through to their own default. "0", "false", "no", "off" → false;
 * anything else non-empty → true.
 */
function parseBoolEnv(value: string | undefined): boolean | undefined {
  if (value === undefined || value === "") return undefined;
  const normalized = value.trim().toLowerCase();
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return true;
}

/**
 * Apply environment variable fallbacks for API keys.
 * Used by both `get()` and `init()` so fresh installs pick up env vars.
 */
function applyEnvFallbacks(parsedConfig: Partial<Config>): Config {
  const version = getCurrentVersion();
  return {
    ...parsedConfig,
    responsibleUseAccepted: parsedConfig.responsibleUseAccepted ?? false,
    defaultHeaders:
      parsedConfig.defaultHeaders ?? DEFAULT_CONFIG.defaultHeaders,
    strikeMode: parsedConfig.strikeMode ?? DEFAULT_CONFIG.strikeMode,
    surfaceIntegrationEnabled:
      parsedConfig.surfaceIntegrationEnabled ??
      parseBoolEnv(process.env.PENSAR_SURFACE_INTEGRATION),
    version,
    openAiAPIKey: parsedConfig.openAiAPIKey ?? process.env.OPENAI_API_KEY,
    anthropicAPIKey:
      parsedConfig.anthropicAPIKey ?? process.env.ANTHROPIC_API_KEY,
    googleAPIKey:
      parsedConfig.googleAPIKey ?? process.env.GOOGLE_GENERATIVE_AI_API_KEY,
    openRouterAPIKey:
      parsedConfig.openRouterAPIKey ?? process.env.OPENROUTER_API_KEY,
    concentrateAPIKey:
      parsedConfig.concentrateAPIKey ?? process.env.CONCENTRATE_API_KEY,
    contextCompactionModel:
      parsedConfig.contextCompactionModel ??
      process.env.PENSAR_CONTEXT_COMPACTION_MODEL,
    contextCompactionEnabled:
      parsedConfig.contextCompactionEnabled ??
      (process.env.PENSAR_CONTEXT_COMPACTION?.toLowerCase() === "legacy"
        ? false
        : undefined),
    contextCompactionThresholdRatio:
      parsedConfig.contextCompactionThresholdRatio ??
      (process.env.PENSAR_CONTEXT_COMPACTION_THRESHOLD
        ? Number(process.env.PENSAR_CONTEXT_COMPACTION_THRESHOLD)
        : undefined),
    inceptionAPIKey:
      parsedConfig.inceptionAPIKey ?? process.env.INCEPTION_API_KEY,
    bedrockAPIKey: parsedConfig.bedrockAPIKey ?? process.env.BEDROCK_API_KEY,
    pensarAPIKey: parsedConfig.pensarAPIKey ?? process.env.PENSAR_API_KEY,
    daytonaAPIKey: parsedConfig.daytonaAPIKey ?? process.env.DAYTONA_API_KEY,
    daytonaOrgId: parsedConfig.daytonaOrgId ?? process.env.DAYTONA_ORG_ID,
    runloopAPIKey: parsedConfig.runloopAPIKey ?? process.env.RUNLOOP_API_KEY,
    braveAPIKey: parsedConfig.braveAPIKey ?? process.env.BRAVE_API_KEY,
  };
}

export async function get(): Promise<Config> {
  const folder = path.join(os.homedir(), ".pensar");
  const file = path.join(folder, "config.json");
  const exists = await fs
    .access(file)
    .then(() => true)
    .catch(() => false);
  if (!exists) {
    await init();
    return applyEnvFallbacks(DEFAULT_CONFIG);
  }
  const config = await fs.readFile(file, "utf8");
  const parsedConfig = JSON.parse(config);
  return applyEnvFallbacks(parsedConfig);
}

export async function update(config: Partial<Config>) {
  const folder = path.join(os.homedir(), ".pensar");
  const file = path.join(folder, "config.json");
  const exists = await fs
    .access(file)
    .then(() => true)
    .catch(() => false);
  const currentConfig = exists
    ? JSON.parse(await fs.readFile(file, "utf8"))
    : DEFAULT_CONFIG;
  const newConfig = { ...currentConfig, ...config };
  await fs.writeFile(file, JSON.stringify(newConfig));
}
