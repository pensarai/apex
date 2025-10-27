import os from "os";
import path from "path";
import fs from "fs/promises";

const CONFIG_DIR_PATH = path.join(os.homedir(), ".pensar");
const CONFIG_FILE_PATH = path.join(CONFIG_DIR_PATH, "config.json");

const DEFAULT_CONFIG: Config = {
  responsibleUseAccepted: false,
};

export interface Config {
  openAiAPIKey?: string | null;
  anthropicAPIKey?: string | null;
  openRouterAPIKey?: string | null;
  bedrockAPIKey?: string | null;
  responsibleUseAccepted: boolean;
  development?: boolean | null;
}

export async function init() {
  const dirExists = await fs
    .access(CONFIG_DIR_PATH)
    .then(() => true)
    .catch(() => false);
  if (!dirExists) {
    await fs.mkdir(CONFIG_DIR_PATH, { recursive: true });
  }
  const fileExists = await fs
    .access(CONFIG_FILE_PATH)
    .then(() => true)
    .catch(() => false);
  if (!fileExists) {
    await fs.writeFile(CONFIG_FILE_PATH, JSON.stringify(DEFAULT_CONFIG));
  }
  return DEFAULT_CONFIG;
}

export async function get(): Promise<Config> {
  const exists = await fs
    .access(CONFIG_FILE_PATH)
    .then(() => true)
    .catch(() => false);
  if (!exists) {
    return await init();
  }
  const config = await fs.readFile(CONFIG_FILE_PATH, "utf8");

  const parsedConfig = JSON.parse(config);

  return {
    ...parsedConfig,
    openAiAPIKey: process.env.OPENAI_API_KEY,
    anthropicAPIKey: process.env.ANTHROPIC_API_KEY,
    openRouterAPIKey: process.env.OPENROUTER_API_KEY,
    bedrockAPIKey: process.env.BEDROCK_API_KEY,
    development: process.env.NODE_ENV === "development"
  };
}

export async function update(config: Partial<Config>) {
  const currentConfig = await get();
  const newConfig = { ...currentConfig, ...config };
  await fs.writeFile(CONFIG_FILE_PATH, JSON.stringify(newConfig));
}

export {
  CONFIG_DIR_PATH,
  CONFIG_FILE_PATH
};