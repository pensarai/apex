import { z } from "zod";
import {
  type CustomProviders,
  loadCustomProviders,
  parseCustomModelId,
  parseCustomProviders,
} from "./customProviders";

const basetenHost =
  /^(model-[a-zA-Z0-9_-]+\.api\.baseten\.co|inference\.baseten\.co)$/;

export function usesBasetenEndpoint(
  model: string,
  configured?: CustomProviders,
): boolean {
  const id = parseCustomModelId(model);
  if (!id) return false;
  const provider = (configured ?? loadCustomProviders())[id.providerId];
  if (!provider) return false;
  const url = new URL(provider.baseUrl);
  return (
    url.protocol === "https:" &&
    (basetenHost.test(url.hostname) ||
      /^Baseten(?:\s|$)/i.test(provider.name ?? ""))
  );
}

const remoteId = z.string().regex(/^[A-Za-z0-9_-]{1,80}$/);
const modelList = z.object({
  data: z.array(
    z.object({
      id: z.string().min(1),
      name: z.string().optional(),
      context_length: z.number().int().positive().optional(),
      max_model_len: z.number().int().positive().optional(),
      max_output_tokens: z.number().int().positive().optional(),
    }),
  ),
});
const deployments = z.object({
  models: z.array(
    z.object({
      id: remoteId,
      name: z.string(),
      production_deployment_id: remoteId.nullable(),
    }),
  ),
});
const config = z.object({
  config: z.object({
    docker_server: z
      .object({ predict_endpoint: z.string(), start_command: z.string() })
      .nullish(),
  }),
});

function httpsUrl(value: string) {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  )
    throw new Error("Expected an HTTPS Baseten endpoint.");
  return url;
}

async function getJson(url: string, key: string, optional = false) {
  const res = await fetch(url, {
    headers: { authorization: `Bearer ${key}` },
    redirect: "error",
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) {
    await res.body?.cancel();
    if (optional && (res.status === 403 || res.status === 404)) return null;
    throw new Error(`Baseten model discovery returned HTTP ${res.status}.`);
  }
  return res.json();
}

function configuredContextLength(command: string) {
  const match =
    /(?:^|\s)--max-model-len(?:=|\s+)["']?(\d+(?:\.\d+)?)([kKmMgG]?)["']?(?=[\s;&|()<>]|$)/.exec(
      command,
    );
  if (!match) return;
  const [, digits, unit] = match;
  const scale: Record<string, number> = {
    k: 1e3,
    K: 2 ** 10,
    m: 1e6,
    M: 2 ** 20,
    g: 1e9,
    G: 2 ** 30,
  };
  const length = Number(digits) * (scale[unit] ?? 1);
  return Number.isSafeInteger(length) && length > 1 ? length : undefined;
}

function model(
  id: string,
  name: string,
  contextLength: number,
  output?: number,
) {
  return {
    id,
    name,
    contextLength,
    maxOutputTokens: Math.min(
      output ?? Math.min(32_768, Math.max(1, Math.floor(contextLength / 2))),
      contextLength - 1,
    ),
  };
}

async function load(key: string, endpoint?: string) {
  const providers: CustomProviders = {};
  if (endpoint) {
    const url = httpsUrl(endpoint);
    if (url.port || !basetenHost.test(url.hostname))
      throw new Error(
        "BASETEN_BASE_URL must point to a Baseten HTTPS endpoint.",
      );
    const base = url.href.replace(/\/+$/, "");
    const list = modelList.parse(await getJson(base + "/models", key));
    if (list.data.length) {
      providers.baseten = {
        name: "Baseten",
        baseUrl: base,
        apiKeyEnv: "BASETEN_API_KEY",
        includeUsage: true,
        models: list.data.map((m) =>
          model(
            m.id,
            m.name ?? m.id,
            m.context_length ?? m.max_model_len ?? 32_768,
            m.max_output_tokens,
          ),
        ),
      };
    }
  } else {
    const management = "https://api.baseten.co/v1/models";
    const { models } = deployments.parse(await getJson(management, key));
    // Reading deployment configuration lists sleeping models without waking their replicas.
    const live = models.flatMap((m) =>
      m.production_deployment_id
        ? [{ ...m, production_deployment_id: m.production_deployment_id }]
        : [],
    );
    for (let offset = 0; offset < live.length; offset += 8) {
      await Promise.all(
        live.slice(offset, offset + 8).map(async (m) => {
          const deployment = m.production_deployment_id;
          const metadata = config.safeParse(
            await getJson(
              `${management}/${m.id}/deployments/${deployment}/config`,
              key,
              true,
            ),
          );
          const server = metadata.success
            ? metadata.data.config.docker_server
            : undefined;
          if (server?.predict_endpoint !== "/v1/chat/completions") return;
          const served =
            /(?:^|\s)--served-model-name(?:=|\s+)["']?([\w./:-]+)/.exec(
              server.start_command,
            )?.[1];
          const length = configuredContextLength(server.start_command);
          if (!served || !length) return;
          providers[`baseten-${m.id}-${deployment}`] = {
            name: "Baseten",
            baseUrl: `https://model-${m.id}.api.baseten.co/deployment/${deployment}/sync/v1`,
            apiKeyEnv: "BASETEN_API_KEY",
            includeUsage: true,
            models: [model(served, m.name, length)],
          };
        }),
      );
    }
  }
  return parseCustomProviders(providers);
}

let cached:
  | {
      key: string;
      endpoint?: string;
      until: number;
      result: Promise<CustomProviders>;
    }
  | undefined;
export async function discoverBaseten(): Promise<CustomProviders> {
  const key = process.env.BASETEN_API_KEY?.trim();
  if (!key) return {};
  const endpoint = process.env.BASETEN_BASE_URL?.trim();
  if (
    cached &&
    cached.key === key &&
    cached.endpoint === endpoint &&
    cached.until > Date.now()
  )
    return cached.result;
  const entry = {
    key,
    endpoint,
    until: Date.now() + 60_000,
    result: load(key, endpoint),
  };
  cached = entry;
  try {
    return await entry.result;
  } catch (error) {
    if (cached === entry) cached = undefined;
    throw error;
  }
}
