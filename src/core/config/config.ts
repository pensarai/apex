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
  openRouterAPIKey?: string | null;
  bedrockAPIKey?: string | null;
  bedrockAccessKeyId?: string | null;
  bedrockSecretAccessKey?: string | null;
  bedrockSessionToken?: string | null;
  bedrockRegion?: string | null;
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
    openAiAPIKey: process.env.OPENAI_API_KEY ?? parsedConfig.openAiAPIKey,
    anthropicAPIKey:
      process.env.ANTHROPIC_API_KEY ?? parsedConfig.anthropicAPIKey,
    openRouterAPIKey:
      process.env.OPENROUTER_API_KEY ?? parsedConfig.openRouterAPIKey,
    bedrockAPIKey: process.env.BEDROCK_API_KEY ?? parsedConfig.bedrockAPIKey,
    bedrockAccessKeyId:
      process.env.AWS_ACCESS_KEY_ID ?? parsedConfig.bedrockAccessKeyId,
    bedrockSecretAccessKey:
      process.env.AWS_SECRET_ACCESS_KEY ?? parsedConfig.bedrockSecretAccessKey,
    bedrockSessionToken:
      process.env.AWS_SESSION_TOKEN ?? parsedConfig.bedrockSessionToken,
    bedrockRegion: process.env.AWS_REGION ?? parsedConfig.bedrockRegion,
    daytonaAPIKey: process.env.DAYTONA_API_KEY ?? parsedConfig.daytonaAPIKey,
    daytonaOrgId: process.env.DAYTONA_ORG_ID ?? parsedConfig.daytonaOrgId,
    runloopAPIKey: process.env.RUNLOOP_API_KEY ?? parsedConfig.runloopAPIKey,
  };
}

export async function update(config: Partial<Config>) {
  const currentConfig = await get();
  const newConfig = { ...currentConfig, ...config };
  const folder = path.join(os.homedir(), ".pensar");
  const file = path.join(folder, "config.json");
  await fs.writeFile(file, JSON.stringify(newConfig));
}
