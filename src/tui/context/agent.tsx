import {
  createContext,
  useContext,
  useState,
  useMemo,
  useCallback,
  useEffect,
  type ReactNode,
} from "react";
import { type ModelInfo } from "../../core/ai";
import { AVAILABLE_MODELS } from "../../core/ai/models";
import { writeErrorLog } from "../../core/logger";
import { getAvailableModels } from "../../core/providers/utils";
import { useConfig } from "./config";

// Preferred defaults by provider (fast + cheap models)
const PREFERRED_DEFAULTS: Record<string, string> = {
  pensar: "pensar:anthropic.claude-haiku-4-5-20251001-v1:0",
  anthropic: "claude-haiku-4-5",
  openai: "gpt-4o-mini",
};

// Provider preference order when multiple are available
// Pensar first: if connected to Pensar Console, prefer managed inference
const PROVIDER_PREFERENCE = [
  "pensar",
  "anthropic",
  "openai",
  "openrouter",
  "bedrock",
];

interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

interface AgentContextValue {
  model: ModelInfo;
  setModel: (model: ModelInfo) => void;
  isModelUserSelected: boolean;
  tokenUsage: TokenUsage;
  addTokenUsage: (input: number, output: number) => void;
  resetTokenUsage: () => void;
  hasExecuted: boolean;
  thinking: boolean;
  setThinking: (thinking: boolean) => void;
  isExecuting: boolean;
  setIsExecuting: (isExecuting: boolean) => void;
}

const AgentContext = createContext<AgentContextValue | null>(null);

export function useAgent() {
  const context = useContext(AgentContext);
  if (!context) {
    throw new Error("useAgent must be used within AgentProvider");
  }
  return context;
}

interface AgentProviderProps {
  children: ReactNode;
}

export function AgentProvider({ children }: AgentProviderProps) {
  const config = useConfig();
  const [model, setModelInternal] = useState<ModelInfo>(AVAILABLE_MODELS[0]!);
  const [tokenUsage, setTokenUsage] = useState<TokenUsage>({
    inputTokens: 0,
    outputTokens: 0,
    totalTokens: 0,
  });
  const [hasExecuted, setHasExecuted] = useState<boolean>(false);
  const [thinking, setThinking] = useState<boolean>(false);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);

  // Derived from config — true when the user has explicitly selected a model
  const isModelUserSelected = !!config.data.selectedModelId;

  // Persist model selection to config
  const setModel = useCallback(
    (newModel: ModelInfo) => {
      setModelInternal(newModel);
      config.update({ selectedModelId: newModel.id }).catch((err) => {
        writeErrorLog(err, "CONFIG");
      });
    },
    [config],
  );

  // Smart default model selection:
  // 1. Restore persisted user selection if still available
  // 2. Prefer Pensar Haiku 4.5 if connected to Pensar Console
  // 3. Fall back to Claude Haiku 4.5 if Anthropic is configured
  // 4. Fall back to GPT-4o Mini if OpenAI is configured
  // 5. Otherwise use first available model
  useEffect(() => {
    const available = getAvailableModels(config.data);
    if (available.length === 0) return;

    // Restore persisted model selection
    const persistedId = config.data.selectedModelId;
    if (persistedId) {
      const persisted = available.find((m) => m.id === persistedId);
      if (persisted) {
        setModelInternal(persisted);
        return;
      }
      // Persisted model is stale — clean it up
      config.update({ selectedModelId: null }).catch((err) => {
        writeErrorLog(err, "CONFIG");
      });
    }

    // Group available models by provider
    const byProvider = new Map<string, ModelInfo[]>();
    for (const m of available) {
      const list = byProvider.get(m.provider) || [];
      list.push(m);
      byProvider.set(m.provider, list);
    }

    // Find best default based on provider preference
    let selectedModel: ModelInfo | null = null;
    for (const provider of PROVIDER_PREFERENCE) {
      const models = byProvider.get(provider);
      if (!models || models.length === 0) continue;

      // Try to find the preferred model for this provider
      const preferredId = PREFERRED_DEFAULTS[provider];
      if (preferredId) {
        const preferred = models.find((m) => m.id === preferredId);
        if (preferred) {
          selectedModel = preferred;
          break;
        }
      }
      // Fall back to first model from this provider
      selectedModel = models[0]!;
      break;
    }

    if (selectedModel) {
      setModelInternal(selectedModel);
    }
  }, [config.data]);

  const addTokenUsage = useCallback((input: number, output: number) => {
    setHasExecuted(true);
    setTokenUsage((prev) => ({
      inputTokens: prev.inputTokens + input,
      outputTokens: prev.outputTokens + output,
      totalTokens: prev.totalTokens + input + output,
    }));
  }, []);

  const resetTokenUsage = useCallback(() => {
    setHasExecuted(false);
    setTokenUsage({ inputTokens: 0, outputTokens: 0, totalTokens: 0 });
  }, []);

  const contextValue = useMemo(
    () => ({
      model,
      setModel,
      isModelUserSelected,
      tokenUsage,
      addTokenUsage,
      resetTokenUsage,
      hasExecuted,
      thinking,
      setThinking,
      isExecuting,
      setIsExecuting,
    }),
    [
      model,
      setModel,
      isModelUserSelected,
      tokenUsage,
      hasExecuted,
      thinking,
      isExecuting,
      addTokenUsage,
      resetTokenUsage,
    ],
  );

  return (
    <AgentContext.Provider value={contextValue}>
      {children}
    </AgentContext.Provider>
  );
}
