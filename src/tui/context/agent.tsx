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
  addRecentModelId,
  type ModelInfo,
  type ReasoningSetting,
  validateReasoningSetting,
} from "../../core/ai";
import { getSavedReasoning } from "../../core/cli/reasoning";
import { writeErrorLog } from "../../core/logger";
import {
  getDefaultModelForConfig,
  getSavedModelForConfig,
} from "../../core/providers/utils";
import { useConfig } from "./config";
import { SessionUsageStore } from "./session-usage";

interface AgentContextValue {
  model: ModelInfo;
  /**
   * Update the active model.
   * Pass `persist = false` for programmatic/initialization calls that should
   * not overwrite the user's saved preference on disk.
   */
  setModel: (model: ModelInfo, persist?: boolean) => void;
  isModelUserSelected: boolean;
  /** Session-scoped usage ownership: per-session totals + context sample. */
  usageStore: SessionUsageStore;
  /** Marks that an agent step has executed (drives the footer status). */
  markExecuted: () => void;
  hasExecuted: boolean;
  thinking: boolean;
  setThinking: (thinking: boolean) => void;
  reasoning: ReasoningSetting | undefined;
  setReasoning: (setting: ReasoningSetting, modelId?: string) => void;
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
    return (
      getSavedModelForConfig(appConfig.data) ??
      getDefaultModelForConfig(appConfig.data) ??
      AVAILABLE_MODELS[0]!
    );
  });
  const [isModelUserSelected, setIsModelUserSelected] =
    useState<boolean>(false);
  const usageStore = useMemo(() => new SessionUsageStore(), []);
  const [hasExecuted, setHasExecuted] = useState<boolean>(false);
  const [thinking, setThinking] = useState<boolean>(false);
  const reasoning = getSavedReasoning(model.id, appConfig.data);
  const setReasoning = useCallback(
    (setting: ReasoningSetting, modelId = model.id) => {
      validateReasoningSetting(
        modelId,
        setting,
        appConfig.data.customProviders,
      );
      appConfig
        .update({
          modelReasoning: {
            ...appConfig.data.modelReasoning,
            [modelId]: setting,
          },
        })
        .catch((err) => writeErrorLog(err, "AGENT_CONTEXT"));
    },
    [
      model.id,
      appConfig.data.modelReasoning,
      appConfig.data.customProviders,
      appConfig.update,
    ],
  );
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [sessionCwd, setSessionCwd] = useState<string | null>(null);

  const recentModelIdsRef = useRef(appConfig.data.recentModelIds ?? []);
  const updateConfig = appConfig.update;

  // Wrapper that marks model as user-selected and persists to config.
  // Pass `persist = false` for programmatic/initialization calls so the
  // user's previously saved preference is not silently overwritten.
  const setModel = useCallback(
    (newModel: ModelInfo, persist = true) => {
      setModelInternal(newModel);
      if (persist) {
        setIsModelUserSelected(true);
        const nextRecentModelIds = addRecentModelId(
          recentModelIdsRef.current,
          newModel.id,
        );
        recentModelIdsRef.current = nextRecentModelIds;

        const configUpdate: {
          selectedModelId: string;
          recentModelIds: string[];
        } = {
          selectedModelId: newModel.id,
          recentModelIds: nextRecentModelIds,
        };
        updateConfig(configUpdate).catch((err) => {
          writeErrorLog(err, "AGENT_CONTEXT");
        });
      }
    },
    [updateConfig],
  );

  useEffect(() => {
    recentModelIdsRef.current = appConfig.data.recentModelIds ?? [];
  }, [appConfig.data.recentModelIds]);

  // Re-evaluate the default model whenever config changes (e.g. after
  // provider setup) unless the user has explicitly picked a model.
  useEffect(() => {
    if (isModelUserSelected) return;

    const cfg = appConfig.data;
    // Honour a previously saved preference
    const savedModel = getSavedModelForConfig(cfg);
    if (savedModel) {
      setModelInternal(savedModel);
      setIsModelUserSelected(true);
      return;
    }

    // Dynamic default based on configured providers
    const defaultModel = getDefaultModelForConfig(cfg);
    if (defaultModel) {
      setModelInternal(defaultModel);
    }
  }, [appConfig.data, isModelUserSelected]);

  const markExecuted = useCallback(() => setHasExecuted(true), []);

  const contextValue = useMemo(
    () => ({
      model,
      setModel,
      isModelUserSelected,
      usageStore,
      markExecuted,
      hasExecuted,
      thinking,
      setThinking,
      reasoning,
      setReasoning,
      isExecuting,
      setIsExecuting,
      sessionCwd,
      setSessionCwd,
    }),
    [
      model,
      setModel,
      isModelUserSelected,
      hasExecuted,
      thinking,
      reasoning,
      setReasoning,
      isExecuting,
      sessionCwd,
      usageStore,
      markExecuted,
    ],
  );

  return (
    <AgentContext.Provider value={contextValue}>
      {children}
    </AgentContext.Provider>
  );
}
