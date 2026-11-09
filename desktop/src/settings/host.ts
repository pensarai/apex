import {
  DEFAULT_LANCE_BUDGET,
  lanceBudgetSchema,
} from "../../../src/core/agents/lanceBudget";
import {
  addRecentModelId,
  getReasoningCapabilities,
  getReasoningChoices,
  validateReasoningSetting,
} from "../../../src/core/ai";
import { getSavedReasoning } from "../../../src/core/cli/reasoning";
import { config } from "../../../src/core/config";
import type { Config } from "../../../src/core/config/config";
import { loadCustomProviders } from "../../../src/core/config/customProviders";
import { parseHeaderLine } from "../../../src/core/http/parse";
import { renderHeaderValue } from "../../../src/core/http/types";
import {
  isObfuscationEnabled,
  setObfuscationEnabled,
} from "../../../src/core/obfuscation";
import {
  getConfiguredProviders,
  hasAnyProviderConfigured,
  verifyApiKey,
} from "../../../src/core/providers";
import {
  getAvailableModels,
  getDefaultModelForConfig,
  getSavedModelForConfig,
} from "../../../src/core/providers/utils";
import { getVisiblePickerModels } from "../../../src/tui/components/model-picker/model-visibility";
import themes from "../../node_modules/.cache/apex-themes.json";
import { createAccount } from "./account";
import type {
  Appearance,
  KeyProvider,
  ServiceKey,
  SettingsChange,
  SettingsRequests,
  SettingsSnapshot,
} from "./contract";

const keys = {
  anthropic: "anthropicAPIKey",
  openai: "openAiAPIKey",
  google: "googleAPIKey",
  openrouter: "openRouterAPIKey",
  concentrate: "concentrateAPIKey",
  inference: "inferenceAPIKey",
  inception: "inceptionAPIKey",
  hoonify: "hoonifyAPIKey",
  bedrock: "bedrockAPIKey",
} as const satisfies Record<KeyProvider, keyof Config>;
const services = [
  "daytonaAPIKey",
  "daytonaOrgId",
  "runloopAPIKey",
  "braveAPIKey",
  "exaAPIKey",
] as const satisfies readonly ServiceKey[];

function appearance(cfg: Config): Appearance {
  return {
    theme: cfg.theme ?? "apex",
    mode: cfg.themeMode ?? "auto",
    transparent: cfg.transparentBackground ?? false,
    obfuscate: isObfuscationEnabled(),
  };
}

export function settingsSnapshot(cfg: Config): SettingsSnapshot {
  const selected = getSavedModelForConfig(cfg) ?? getDefaultModelForConfig(cfg);
  const available = getAvailableModels(cfg);
  if (selected && !available.some((m) => m.id === selected.id))
    available.push(selected);
  const envProviders = loadCustomProviders();
  return {
    providers: getConfiguredProviders(cfg).map(({ id, name, configured }) => ({
      id,
      name,
      configured,
    })),
    hasProvider: hasAnyProviderConfigured(cfg),
    local: { url: cfg.localModelUrl ?? "", name: cfg.localModelName ?? "" },
    custom: Object.entries(cfg.customProviders ?? {}).map(([id, p]) => ({
      id,
      name: p.name ?? id,
      definition: JSON.stringify(
        {
          name: p.name,
          baseUrl: p.baseUrl,
          apiType: p.apiType,
          apiKeyEnv: p.apiKeyEnv,
          models: p.models,
        },
        null,
        2,
      ),
      fromEnvironment: Object.hasOwn(envProviders, id),
    })),
    catalogError: cfg.hoonifyCatalogError,
    models: getVisiblePickerModels(available, selected ?? undefined).map(
      (m) => ({
        id: m.id,
        name: m.name,
        provider: m.provider,
        reasoning: getSavedReasoning(m.id, cfg),
        choices: getReasoningChoices(
          getReasoningCapabilities(m.id, cfg.customProviders),
        ),
      }),
    ),
    selected: selected?.id,
    recent: cfg.recentModelIds ?? [],
    advanced: {
      mode: cfg.lanceMode ? "lance" : cfg.strikeMode ? "strike" : "standard",
      findingPolicy: cfg.findingPolicy ?? "native",
      budget: cfg.lanceBudget ?? DEFAULT_LANCE_BUDGET,
      surface: cfg.surfaceIntegrationEnabled ?? true,
    },
    appearance: appearance(cfg),
    headers: Object.entries(cfg.defaultHeaders ?? {}).map(([name, value]) => ({
      name,
      display: renderHeaderValue(name, value, false),
    })),
    services: {
      daytonaAPIKey: !!cfg.daytonaAPIKey,
      daytonaOrgId: !!cfg.daytonaOrgId,
      runloopAPIKey: !!cfg.runloopAPIKey,
      braveAPIKey: !!cfg.braveAPIKey,
      exaAPIKey: !!cfg.exaAPIKey,
    },
  };
}

async function change(action: SettingsChange) {
  switch (action.kind) {
    case "model": {
      const cfg = await config.get();
      if (!settingsSnapshot(cfg).models.some((m) => m.id === action.id))
        throw new Error("Model is unavailable. Refresh the model list.");
      if (action.reasoning !== undefined)
        validateReasoningSetting(
          action.id,
          action.reasoning,
          cfg.customProviders,
        );
      await config.update({
        selectedModelId: action.id,
        recentModelIds: addRecentModelId(cfg.recentModelIds ?? [], action.id),
        ...(action.reasoning !== undefined && {
          modelReasoning: {
            ...cfg.modelReasoning,
            [action.id]: action.reasoning,
          },
        }),
      });
      break;
    }
    case "provider": {
      if (!Object.hasOwn(keys, action.id)) throw new Error("Unknown provider.");
      const apiKey = action.key === null ? null : action.key.trim();
      if (apiKey !== null) {
        if (!apiKey) throw new Error("Enter an API key.");
        const result = await verifyApiKey(action.id, apiKey);
        if (!result.valid)
          throw new Error(
            (result.error || "Invalid API key.").replaceAll(
              apiKey,
              "[redacted]",
            ),
          );
      }
      await config.update({ [keys[action.id]]: apiKey });
      break;
    }
    case "custom": {
      let definition: unknown;
      try {
        definition =
          action.definition === null ? null : JSON.parse(action.definition);
      } catch {
        throw new Error("Invalid provider JSON.");
      }
      if (action.definition !== null && definition === null)
        throw new Error("Expected a provider definition.");
      await config.updateCustomProvider(action.id, definition);
      break;
    }
    case "local": {
      const url = action.url.trim();
      const name = action.name.trim();
      if (url || name) {
        if (!name) throw new Error("Enter a model ID.");
        const parsed = new URL(url);
        if (
          !["http:", "https:"].includes(parsed.protocol) ||
          parsed.username ||
          parsed.password ||
          parsed.search ||
          parsed.hash
        )
          throw new Error(
            "Enter an HTTP or HTTPS endpoint without credentials.",
          );
      }
      await config.update({
        localModelUrl: url || null,
        localModelName: name || null,
      });
      break;
    }
    case "advanced": {
      const { mode, findingPolicy, budget, surface } = action.value;
      if (
        !["standard", "strike", "lance"].includes(mode) ||
        !["native", "external"].includes(findingPolicy) ||
        typeof surface !== "boolean"
      )
        throw new Error("Unknown execution setting.");
      await config.update({
        strikeMode: mode === "strike",
        lanceMode: mode === "lance",
        findingPolicy,
        surfaceIntegrationEnabled: surface,
        ...(mode === "lance" && {
          lanceBudget: lanceBudgetSchema.parse(budget),
        }),
      });
      break;
    }
    case "appearance": {
      const { theme, mode, transparent, obfuscate } = action.value;
      if (
        !Object.hasOwn(themes, theme) ||
        !["light", "dark", "auto"].includes(mode) ||
        typeof transparent !== "boolean" ||
        typeof obfuscate !== "boolean"
      )
        throw new Error("Unknown appearance setting.");
      await config.update({
        theme,
        themeMode: mode,
        transparentBackground: transparent,
      });
      setObfuscationEnabled(obfuscate);
      if (obfuscate) process.env.PENSAR_OBFUSCATE = "1";
      else delete process.env.PENSAR_OBFUSCATE;
      break;
    }
    case "service":
      if (!services.includes(action.id)) throw new Error("Unknown service.");
      await config.update({ [action.id]: action.value?.trim() || null });
      break;
    case "header": {
      if (action.name.includes(":") || action.name.trim() !== action.name)
        throw new Error("Invalid header name.");
      const parsed = parseHeaderLine(`${action.name}: ${action.value ?? ""}`);
      if (!parsed.ok) throw new Error(`Invalid header (${parsed.error.kind}).`);
      const cfg = await config.get();
      const headers = { ...cfg.defaultHeaders };
      for (const name of Object.keys(headers))
        if (name.toLowerCase() === parsed.value.name.toLowerCase())
          delete headers[name];
      if (action.value !== null)
        Object.defineProperty(headers, parsed.value.name, {
          value: parsed.value.value,
          enumerable: true,
          configurable: true,
        });
      await config.update({
        defaultHeaders: headers,
        defaultHeadersUpdatedAt: new Date().toISOString(),
      });
      break;
    }
    default:
      throw new Error("Unknown settings change.");
  }
}

export function createSettingsHost(opts: {
  openExternal: (url: string) => void;
  requireAcceptance: () => void;
}) {
  const account = createAccount(opts.openExternal);
  let pending = Promise.resolve();
  const snapshot = async () => settingsSnapshot(await config.get());
  if (process.env.PENSAR_OBFUSCATE === "1") setObfuscationEnabled(true);
  return {
    dispose: account.dispose,
    requests: {
      desktopSettings: async () => {
        opts.requireAcceptance();
        return snapshot();
      },
      desktopAppearance: async () => appearance(await config.get()),
      changeSettings: async (action: SettingsChange) => {
        opts.requireAcceptance();
        const write = pending.then(() => change(action));
        pending = write.catch(() => {});
        await write;
        return snapshot();
      },
      accountAction: async (
        action: SettingsRequests["accountAction"]["params"],
      ) => {
        opts.requireAcceptance();
        return account.action(action);
      },
      accountStatus: async () => {
        opts.requireAcceptance();
        return account.status();
      },
      desktopBalance: async () => {
        opts.requireAcceptance();
        return account.balance();
      },
    },
  };
}
