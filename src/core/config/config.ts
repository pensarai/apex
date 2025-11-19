import os from "os";
import path from "path";
import fs from "fs/promises";

const DEFAULT_CONFIG: Config = {
  responsibleUseAccepted: false,
};

export interface Config {
  openAiAPIKey?: string | null;
  anthropicAPIKey?: string | null;
  openRouterAPIKey?: string | null;
  bedrockAPIKey?: string | null;
  responsibleUseAccepted: boolean;
  // Remote execution providers
  daytonaAPIKey?: string | null;
  daytonaOrgId?: string | null;
  runloopAPIKey?: string | null;
  // Braintrust integration
  braintrustAPIKey?: string | null;
  braintrustProjectName?: string | null;
  braintrustClientId?: string | null;
  braintrustEnvironment?: 'dev' | 'staging' | 'prod' | null;
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
  return DEFAULT_CONFIG;
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

  return {
    ...parsedConfig,
    openAiAPIKey: process.env.OPENAI_API_KEY,
    anthropicAPIKey: process.env.ANTHROPIC_API_KEY,
    openRouterAPIKey: process.env.OPENROUTER_API_KEY,
    bedrockAPIKey: process.env.BEDROCK_API_KEY,
    daytonaAPIKey: process.env.DAYTONA_API_KEY,
    daytonaOrgId: process.env.DAYTONA_ORG_ID,
    runloopAPIKey: process.env.RUNLOOP_API_KEY,
    // Braintrust config comes from file only (no env var override)
  };
}

export async function update(config: Partial<Config>) {
  const currentConfig = await get();
  const newConfig = { ...currentConfig, ...config };
  const folder = path.join(os.homedir(), ".pensar");
  const file = path.join(folder, "config.json");
  await fs.writeFile(file, JSON.stringify(newConfig));
}
