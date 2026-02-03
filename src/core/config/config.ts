import os from "os";
import path from "path";
import fs from "fs/promises";
import { Installation } from "../installation";

const DEFAULT_CONFIG: Config = {
  responsibleUseAccepted: false,
};

export interface Config {
  version?: string;
  openAiAPIKey?: string | null;
  anthropicAPIKey?: string | null;
  openRouterAPIKey?: string | null;
  bedrockAPIKey?: string | null;
  basetenAPIKey?: string | null;
  responsibleUseAccepted: boolean;
  // Remote execution providers
  daytonaAPIKey?: string | null;
  daytonaOrgId?: string | null;
  runloopAPIKey?: string | null;
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

  const version = await Installation.getVersion();
  return {...DEFAULT_CONFIG, version };
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

  const version = await Installation.getVersion();

  return {
    ...parsedConfig,
    version: version,
    openAiAPIKey: process.env.OPENAI_API_KEY,
    anthropicAPIKey: process.env.ANTHROPIC_API_KEY,
    openRouterAPIKey: process.env.OPENROUTER_API_KEY,
    bedrockAPIKey: process.env.BEDROCK_API_KEY,
    basetenAPIKey: process.env.BASETEN_API_KEY,
    daytonaAPIKey: process.env.DAYTONA_API_KEY,
    daytonaOrgId: process.env.DAYTONA_ORG_ID,
    runloopAPIKey: process.env.RUNLOOP_API_KEY,
  };
}

export async function update(config: Partial<Config>) {
  const currentConfig = await get();
  const newConfig = { ...currentConfig, ...config };
  const folder = path.join(os.homedir(), ".pensar");
  const file = path.join(folder, "config.json");
  await fs.writeFile(file, JSON.stringify(newConfig));
}
