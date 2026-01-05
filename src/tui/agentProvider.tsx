import { createContext, useContext, useState, useMemo, useCallback, useEffect, type ReactNode } from "react";
import { type ModelInfo } from "../core/ai";
import { AVAILABLE_MODELS } from "../core/ai/models";
import { get as getConfig } from "../core/config/config";
import { getAvailableModels } from "../core/providers/utils";

// Preferred defaults by provider (fast + cheap models)
const PREFERRED_DEFAULTS: Record<string, string> = {
  anthropic: "claude-haiku-4-5",
  openai: "gpt-4o-mini",
};

// Provider preference order when multiple are available
const PROVIDER_PREFERENCE = ["anthropic", "openai", "openrouter", "bedrock"];

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
  const [model, setModelInternal] = useState<ModelInfo>(AVAILABLE_MODELS[0]!);
  const [isModelUserSelected, setIsModelUserSelected] = useState<boolean>(false);
  const [tokenUsage, setTokenUsage] = useState<TokenUsage>({
    inputTokens: 0,
    outputTokens: 0,
    totalTokens: 0,
  });
  const [hasExecuted, setHasExecuted] = useState<boolean>(false);
  const [thinking, setThinking] = useState<boolean>(false);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);

  // Wrapper that marks model as user-selected
  const setModel = useCallback((newModel: ModelInfo) => {
    setModelInternal(newModel);
    setIsModelUserSelected(true);
  }, []);

  // Smart default model selection:
  // 1. Prefer Claude Haiku 4.5 if Anthropic is configured
  // 2. Fall back to GPT-4o Mini if OpenAI is configured
  // 3. Otherwise use first available model
  useEffect(() => {
    getConfig().then((config) => {
      const available = getAvailableModels(config);
      if (available.length === 0) return;

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
          const preferred = models.find(m => m.id === preferredId);
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
        // Don't mark as user-selected since this is auto-default
      }
    }).catch(() => {});
  }, []);

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
    [model, setModel, isModelUserSelected, tokenUsage, hasExecuted, thinking, isExecuting, addTokenUsage, resetTokenUsage]
  );

  return (
    <AgentContext.Provider value={contextValue}>
      {children}
    </AgentContext.Provider>
  );
}
