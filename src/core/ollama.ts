import { isIP } from "node:net";
import { z } from "zod";

const modelSchema = z.object({
  name: z.string().trim().min(1),
  capabilities: z.array(z.string()).optional(),
  remote_model: z.string().optional(),
  context_length: z.number().int().min(4).optional(),
});
const catalogSchema = z.object({ models: z.array(modelSchema) });

export interface OllamaCatalog {
  baseURL: string;
  models: {
    id: string;
    contextLength: number;
    maxOutputTokens: number;
    running: boolean;
  }[];
}

export interface OllamaModelLoadEvent {
  model: string;
  status: "loading" | "ready" | "failed" | "cancelled";
  elapsedMs: number;
  /** Ollama's allocated context window, reported on "ready". */
  contextLength?: number;
}

/** Preload before prompt fitting so budgets use Ollama's allocated context. */
export async function prepareOllamaModel(
  id: string,
  catalog: OllamaCatalog | undefined,
  signal?: AbortSignal,
  onStatus?: (event: OllamaModelLoadEvent) => void,
): Promise<void> {
  const { model, baseURL } = resolveOllamaModel(id, catalog);
  const controller = new AbortController();
  const requestSignal = AbortSignal.any([
    controller.signal,
    AbortSignal.timeout(300_000),
    ...(signal ? [signal] : []),
  ]);
  let loading = false;
  const startedAt = Date.now();
  const report = (
    status: OllamaModelLoadEvent["status"],
    contextLength?: number,
  ) =>
    onStatus?.({
      model: id,
      status,
      elapsedMs: Date.now() - startedAt,
      ...(contextLength === undefined ? {} : { contextLength }),
    });
  const readRunning = async () => {
    try {
      const response = await fetch(`${baseURL}/api/ps`, {
        signal: AbortSignal.any([requestSignal, AbortSignal.timeout(1_000)]),
        redirect: "error",
      });
      if (!response.ok) return undefined;
      return catalogSchema
        .parse(await response.json())
        .models.find((item) => item.name === model.id);
    } catch {
      requestSignal.throwIfAborted();
      // Older Ollama servers do not expose allocated-context metadata.
      return undefined;
    }
  };
  try {
    requestSignal.throwIfAborted();
    let running = await readRunning();
    if (!running) {
      loading = true;
      report("loading");
      // An empty generation loads installed weights without generating or pulling.
      const response = await fetch(`${baseURL}/api/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: model.id, stream: false }),
        signal: requestSignal,
        redirect: "error",
      });
      const result = z
        .object({ done: z.boolean().optional(), error: z.string().optional() })
        .parse(await response.json());
      if (!response.ok || result.error || result.done !== true) {
        throw new Error(
          result.error || `Ollama returned HTTP ${response.status}`,
        );
      }
      running = await readRunning();
    }
    requestSignal.throwIfAborted();
    model.contextLength = running?.context_length ?? 4_096;
    model.maxOutputTokens = Math.min(
      4_096,
      Math.floor(model.contextLength / 4),
    );
    model.running = true;
    if (loading) report("ready", model.contextLength);
  } catch (error) {
    if (loading) report(signal?.aborted ? "cancelled" : "failed");
    signal?.throwIfAborted();
    throw new Error(
      `Could not load Ollama model ${model.id}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  } finally {
    controller.abort();
  }
}

export async function discoverOllama(
  signal?: AbortSignal,
): Promise<OllamaCatalog | undefined> {
  const controller = new AbortController();
  try {
    const host = process.env.OLLAMA_HOST?.trim() || "http://127.0.0.1:11434";
    const hasScheme = host.includes("://");
    const address = isIP(host) === 6 ? `[${host}]` : host;
    const url = new URL(hasScheme ? host : `http://${address}`);
    if (!["http:", "https:"].includes(url.protocol)) return undefined;
    if (!hasScheme && !/:\d+(?:\/|$)/.test(address)) url.port = "11434";
    if (url.hostname === "0.0.0.0") url.hostname = "127.0.0.1";
    if (url.hostname === "[::]") url.hostname = "[::1]";
    const baseURL = url.toString().replace(/\/+$/, "");
    const timeout = AbortSignal.timeout(1_000);
    const requestSignal = AbortSignal.any([
      controller.signal,
      timeout,
      ...(signal ? [signal] : []),
    ]);
    const read = async (endpoint: string) => {
      const response = await fetch(`${baseURL}/api/${endpoint}`, {
        signal: requestSignal,
        redirect: "error",
      });
      if (!response.ok) throw new Error("Ollama discovery failed");
      return catalogSchema.parse(await response.json()).models;
    };
    const [installed, running] = await Promise.all([
      read("tags"),
      // Older servers may not expose running-model metadata.
      read("ps").catch(() => []),
    ]);
    const unique = new Map(installed.map((model) => [model.name, model]));
    const models = [...unique.values()]
      .filter(
        (model) =>
          !model.remote_model &&
          (!model.capabilities || model.capabilities.includes("completion")),
      )
      .map((model) => {
        const loaded = running.find((item) => item.name === model.name);
        // The GGUF's maximum context is not Ollama's allocated context.
        const contextLength = loaded?.context_length ?? 4_096;
        return {
          id: model.name,
          contextLength,
          maxOutputTokens: Math.min(4_096, Math.floor(contextLength / 4)),
          running: !!loaded,
        };
      })
      .sort((a, b) => Number(b.running) - Number(a.running));
    return { baseURL, models };
  } catch {
    // Ollama is optional; an absent or unresponsive daemon must not block Apex.
    return undefined;
  } finally {
    controller.abort();
  }
}

export function resolveOllamaModel(id: string, catalog?: OllamaCatalog) {
  const model = catalog?.models.find((item) => `ollama:${item.id}` === id);
  if (!catalog || !model)
    throw new Error(
      "Ollama model is unavailable. Start Ollama with the model installed, then reopen /models.",
    );
  return { model, baseURL: catalog.baseURL };
}
