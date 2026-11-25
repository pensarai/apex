import { basename } from "node:path/posix";
import { parseArgs } from "node:util";
import { parse, type Node as ShellNode } from "unbash";
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

function servingCommands(node: ShellNode): string[][] {
  if (node.type === "Statement") return servingCommands(node.command);
  if ("commands" in node) return node.commands.flatMap(servingCommands);
  if (node.type === "If")
    return [node.clause, node.then, ...(node.else ? [node.else] : [])].flatMap(
      servingCommands,
    );
  if (node.type === "Case")
    return node.items.flatMap((item) => servingCommands(item.body));
  if ("body" in node && typeof node.body !== "string")
    return servingCommands(node.body);
  if (node.type !== "Command" || !node.name) return [];
  const argv = [node.name.value, ...node.suffix.map((word) => word.value)];
  if (argv[0] === "exec") argv.splice(0, argv[1] === "--" ? 2 : 1);
  const executable = basename(argv[0] ?? "");
  if (executable === "sh" || executable === "bash") {
    const { tokens } = parseArgs({
      args: argv.slice(1),
      options: {
        o: { type: "string" },
        O: { type: "string" },
        rcfile: { type: "string" },
        "init-file": { type: "string" },
      },
      strict: false,
      allowPositionals: true,
      tokens: true,
    });
    const script = tokens.find((token) => token.kind === "positional");
    return script &&
      tokens.some(
        (token) =>
          token.kind === "option" &&
          token.name === "c" &&
          token.index < script.index,
      )
      ? parseServingCommands(script.value)
      : [];
  }
  if (executable === "echo" || executable === "printf") return [];
  const serve = argv.findIndex(
    (arg, i) => basename(arg) === "vllm" && argv[i + 1] === "serve",
  );
  const start = serve === -1 ? 1 : serve + 2;
  const end = argv.indexOf("--", start);
  const args = argv.slice(start, end === -1 ? undefined : end);
  return serve >= 0 || optionValue(args, "--served-model-name") ? [args] : [];
}

function parseServingCommands(script: string) {
  const parsed = parse(script);
  return parsed.errors?.length ? [] : parsed.commands.flatMap(servingCommands);
}

function optionValue(args: string[], flag: string) {
  const prefix = `${flag}=`;
  const i = args.findLastIndex((arg) => arg === flag || arg.startsWith(prefix));
  if (i === -1) return;
  return args[i] === flag ? args[i + 1] : args[i].slice(prefix.length);
}

function configuredContextLength(value: string) {
  const match = /^(\d+(?:\.\d+)?)([kKmMgG]?)$/.exec(value);
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
          const candidates = parseServingCommands(server.start_command).map(
            (args) => ({
              served: optionValue(args, "--served-model-name"),
              length: configuredContextLength(
                optionValue(args, "--max-model-len") ?? "",
              ),
            }),
          );
          const [first] = candidates;
          if (
            !first?.served ||
            !/^[\w./:-]+$/.test(first.served) ||
            !first.length
          )
            return;
          if (
            !candidates.every(
              (c) => c.served === first.served && c.length === first.length,
            )
          )
            return;
          providers[`baseten-${m.id}-${deployment}`] = {
            name: "Baseten",
            baseUrl: `https://model-${m.id}.api.baseten.co/deployment/${deployment}/sync/v1`,
            apiKeyEnv: "BASETEN_API_KEY",
            includeUsage: true,
            models: [model(first.served, m.name, first.length)],
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
