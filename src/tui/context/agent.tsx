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
import { update as updateConfig } from "../../core/config/config";
import {
  getAvailableModels,
  getDefaultModelForConfig,
} from "../../core/providers/utils";
import { writeErrorLog } from "../../core/logger";
import { useConfig } from "./config";

interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  cachedTokens: number;
  cacheWriteTokens: number;
}

interface AgentContextValue {
  model: ModelInfo;
  /**
   * Update the active model.
   * Pass `persist = false` for programmatic/initialization calls that should
   * not overwrite the user's saved preference on disk.
   */
  setModel: (model: ModelInfo, persist?: boolean) => void;
  isModelUserSelected: boolean;
  tokenUsage: TokenUsage;
  addTokenUsage: (input: number, output: number) => void;
  addCacheUsage: (cacheRead: number, cacheWrite: number) => void;
  resetTokenUsage: () => void;
  hasExecuted: boolean;
  thinking: boolean;
  setThinking: (thinking: boolean) => void;
  isExecuting: boolean;
  setIsExecuting: (isExecuting: boolean) => void;
  /** The agent's working directory (session rootPath), shown in footer. */
  sessionCwd: string | null;
  setSessionCwd: (cwd: string | null) => void;
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
  const appConfig = useConfig();

  const [model, setModelInternal] = useState<ModelInfo>(() => {
    return getDefaultModelForConfig(appConfig.data) ?? AVAILABLE_MODELS[0]!;
  });
  const [isModelUserSelected, setIsModelUserSelected] =
    useState<boolean>(false);
  const [tokenUsage, setTokenUsage] = useState<TokenUsage>({
    inputTokens: 0,
    outputTokens: 0,
    totalTokens: 0,
    cachedTokens: 0,
    cacheWriteTokens: 0,
  });
  const [hasExecuted, setHasExecuted] = useState<boolean>(false);
  const [thinking, setThinking] = useState<boolean>(false);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [sessionCwd, setSessionCwd] = useState<string | null>(null);

  // Wrapper that marks model as user-selected and persists to config.
  // Pass `persist = false` for programmatic/initialization calls so the
  // user's previously saved preference is not silently overwritten.
  const setModel = useCallback((newModel: ModelInfo, persist = true) => {
    setModelInternal(newModel);
    if (persist) {
      setIsModelUserSelected(true);
      updateConfig({ selectedModelId: newModel.id }).catch((err) => {
        writeErrorLog(err, "AGENT_CONTEXT");
      });
    }
  }, []);

  // Re-evaluate the default model whenever config changes (e.g. after
  // provider setup) unless the user has explicitly picked a model.
  useEffect(() => {
    if (isModelUserSelected) return;

    const cfg = appConfig.data;
    const available = getAvailableModels(cfg);
    if (available.length === 0) return;

    // Honour a previously saved preference
    if (cfg.selectedModelId) {
      const savedModel = available.find((m) => m.id === cfg.selectedModelId);
      if (savedModel) {
        setModelInternal(savedModel);
        setIsModelUserSelected(true);
        return;
      }
    }

    // Dynamic default based on configured providers
    const defaultModel = getDefaultModelForConfig(cfg);
    if (defaultModel) {
      setModelInternal(defaultModel);
    }
  }, [appConfig.data, isModelUserSelected]);

  const addTokenUsage = useCallback((input: number, output: number) => {
    setHasExecuted(true);
    setTokenUsage((prev) => ({
      ...prev,
      inputTokens: prev.inputTokens + input,
      outputTokens: prev.outputTokens + output,
      totalTokens: prev.totalTokens + input + output,
    }));
  }, []);

  const addCacheUsage = useCallback((cacheRead: number, cacheWrite: number) => {
    setTokenUsage((prev) => ({
      ...prev,
      cachedTokens: prev.cachedTokens + cacheRead,
      cacheWriteTokens: prev.cacheWriteTokens + cacheWrite,
    }));
  }, []);

  const resetTokenUsage = useCallback(() => {
    setHasExecuted(false);
    setTokenUsage({
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      cachedTokens: 0,
      cacheWriteTokens: 0,
    });
  }, []);

  const contextValue = useMemo(
    () => ({
      model,
      setModel,
      isModelUserSelected,
      tokenUsage,
      addTokenUsage,
      addCacheUsage,
      resetTokenUsage,
      hasExecuted,
      thinking,
      setThinking,
      isExecuting,
      setIsExecuting,
      sessionCwd,
      setSessionCwd,
    }),
    [
      model,
      setModel,
      isModelUserSelected,
      tokenUsage,
      hasExecuted,
      thinking,
      isExecuting,
      sessionCwd,
      addTokenUsage,
      addCacheUsage,
      resetTokenUsage,
    ],
  );

  return (
    <AgentContext.Provider value={contextValue}>
      {children}
    </AgentContext.Provider>
  );
}
