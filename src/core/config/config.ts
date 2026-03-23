import os from "os";
import path from "path";
import fs from "fs/promises";
import { getCurrentVersion } from "../installation";

const DEFAULT_CONFIG: Config = {
  responsibleUseAccepted: false,
};

export interface Config {
  version?: string;
  openAiAPIKey?: string | null;
  anthropicAPIKey?: string | null;
  googleAPIKey?: string | null;
  openRouterAPIKey?: string | null;
  inceptionAPIKey?: string | null;
  bedrockAPIKey?: string | null;
  pensarAPIKey?: string | null;
  responsibleUseAccepted: boolean;
  // Remote execution providers
  daytonaAPIKey?: string | null;
  daytonaOrgId?: string | null;
  runloopAPIKey?: string | null;
  // Local LLM
  localModelUrl?: string | null;
  localModelName?: string | null;
  // Theme preferences
  theme?: string;
  themeMode?: "dark" | "light" | "auto";
  // Model preference
  selectedModelId?: string | null;
  // WorkOS CLI auth (replaces pensarAPIKey for new auth flow)
  accessToken?: string | null;
  refreshToken?: string | null;
  workspaceId?: string | null;
  workspaceSlug?: string | null;
  // Gateway request signing key (server-issued)
  gatewaySigningKey?: string | null;
  // Gateway URL for inference (server-issued, bypasses CloudFront timeout)
  gatewayUrl?: string | null;
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

export async function get(): Promise<Config> {
  const folder = path.join(os.homedir(), ".pensar");
  const file = path.join(folder, "config.json");
  const exists = await fs
    .access(file)
    .then(() => true)
    .catch(() => false);
  if (!exists) {
    return await init();
  }
  const config = await fs.readFile(file, "utf8");

  const parsedConfig = JSON.parse(config);

  const version = getCurrentVersion();

  return {
    ...parsedConfig,
    version: version,
    openAiAPIKey: parsedConfig.openAiAPIKey ?? process.env.OPENAI_API_KEY,
    anthropicAPIKey:
      parsedConfig.anthropicAPIKey ?? process.env.ANTHROPIC_API_KEY,
    googleAPIKey:
      parsedConfig.googleAPIKey ?? process.env.GOOGLE_GENERATIVE_AI_API_KEY,
    openRouterAPIKey:
      parsedConfig.openRouterAPIKey ?? process.env.OPENROUTER_API_KEY,
    inceptionAPIKey:
      parsedConfig.inceptionAPIKey ?? process.env.INCEPTION_API_KEY,
    bedrockAPIKey: parsedConfig.bedrockAPIKey ?? process.env.BEDROCK_API_KEY,
    pensarAPIKey: parsedConfig.pensarAPIKey ?? process.env.PENSAR_API_KEY,
    daytonaAPIKey: parsedConfig.daytonaAPIKey ?? process.env.DAYTONA_API_KEY,
    daytonaOrgId: parsedConfig.daytonaOrgId ?? process.env.DAYTONA_ORG_ID,
    runloopAPIKey: parsedConfig.runloopAPIKey ?? process.env.RUNLOOP_API_KEY,
  };
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
