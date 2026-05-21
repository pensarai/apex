import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  AVAILABLE_MODELS,
  DEFAULT_OPENAI_REASONING_EFFORT,
  getOpenAIReasoningEfforts,
  type ModelInfo,
  modelSupportsThinking,
  type OpenAIReasoningEffort,
} from "../../core/ai";
import { update as updateConfig } from "../../core/config/config";
import { writeErrorLog } from "../../core/logger";
import {
  getAvailableModels,
  getDefaultModelForConfig,
} from "../../core/providers/utils";
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
  /** Whether extended thinking is enabled for supported models (persisted to config). */
  reasoningEnabled: boolean;
  setReasoningEnabled: (enabled: boolean) => void;
  openAIReasoningEffort: OpenAIReasoningEffort;
  setOpenAIReasoningEffort: (effort: OpenAIReasoningEffort) => void;
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
  const [reasoningEnabled, setReasoningEnabledInternal] = useState<boolean>(
    () => appConfig.data?.reasoningEnabled ?? false,
  );
  const [openAIReasoningEffort, setOpenAIReasoningEffortInternal] =
    useState<OpenAIReasoningEffort>(
      () =>
        appConfig.data?.openAIReasoningEffort ??
        DEFAULT_OPENAI_REASONING_EFFORT,
    );
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [sessionCwd, setSessionCwd] = useState<string | null>(null);

  const reasoningEnabledRef = useRef(reasoningEnabled);
  reasoningEnabledRef.current = reasoningEnabled;
  const openAIReasoningEffortRef = useRef(openAIReasoningEffort);
  openAIReasoningEffortRef.current = openAIReasoningEffort;

  // Wrapper that marks model as user-selected and persists to config.
  // Pass `persist = false` for programmatic/initialization calls so the
  // user's previously saved preference is not silently overwritten.
  const setModel = useCallback((newModel: ModelInfo, persist = true) => {
    setModelInternal(newModel);
    if (persist) {
      setIsModelUserSelected(true);
      const configUpdate: {
        selectedModelId: string;
        reasoningEnabled?: boolean;
        openAIReasoningEffort?: OpenAIReasoningEffort;
      } = {
        selectedModelId: newModel.id,
      };
      if (reasoningEnabledRef.current && !modelSupportsThinking(newModel.id)) {
        configUpdate.reasoningEnabled = false;
        setReasoningEnabledInternal(false);
      }
      const supportedOpenAIEfforts = getOpenAIReasoningEfforts(newModel.id);
      if (
        supportedOpenAIEfforts.length > 0 &&
        !supportedOpenAIEfforts.includes(openAIReasoningEffortRef.current)
      ) {
        configUpdate.openAIReasoningEffort = DEFAULT_OPENAI_REASONING_EFFORT;
        setOpenAIReasoningEffortInternal(DEFAULT_OPENAI_REASONING_EFFORT);
      }
      updateConfig(configUpdate).catch((err) => {
        writeErrorLog(err, "AGENT_CONTEXT");
      });
    }
  }, []);

  const setReasoningEnabled = useCallback((enabled: boolean) => {
    setReasoningEnabledInternal(enabled);
    updateConfig({ reasoningEnabled: enabled }).catch((err) => {
      writeErrorLog(err, "AGENT_CONTEXT");
    });
  }, []);

  const setOpenAIReasoningEffort = useCallback(
    (effort: OpenAIReasoningEffort) => {
      setOpenAIReasoningEffortInternal(effort);
      updateConfig({ openAIReasoningEffort: effort }).catch((err) => {
        writeErrorLog(err, "AGENT_CONTEXT");
      });
    },
    [],
  );

  // Sync reasoningEnabled when config loads asynchronously
  useEffect(() => {
    if (appConfig.data?.reasoningEnabled != null) {
      setReasoningEnabledInternal(appConfig.data.reasoningEnabled);
    }
  }, [appConfig.data?.reasoningEnabled]);

  useEffect(() => {
    if (appConfig.data?.openAIReasoningEffort != null) {
      setOpenAIReasoningEffortInternal(appConfig.data.openAIReasoningEffort);
    }
  }, [appConfig.data?.openAIReasoningEffort]);

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
      reasoningEnabled,
      setReasoningEnabled,
      openAIReasoningEffort,
      setOpenAIReasoningEffort,
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
      reasoningEnabled,
      openAIReasoningEffort,
      isExecuting,
      sessionCwd,
      addTokenUsage,
      addCacheUsage,
      resetTokenUsage,
      setOpenAIReasoningEffort,
    ],
  );

  return (
    <AgentContext.Provider value={contextValue}>
      {children}
    </AgentContext.Provider>
  );
}
