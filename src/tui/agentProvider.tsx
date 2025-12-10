import { createContext, useContext, useState, useMemo, useCallback, type ReactNode } from "react";
import { type ModelInfo } from "../core/ai";
import { AVAILABLE_MODELS } from "../core/ai/models";

interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

interface AgentContextValue {
  model: ModelInfo;
  setModel: (model: ModelInfo) => void;
  tokenCount: number;
  setTokenCount: (tokenCount: number) => void;
  addTokens: (tokens: number) => void;
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
  const [model, setModel] = useState<ModelInfo>(AVAILABLE_MODELS[0]!); // Default to first model
  const [tokenCount, setTokenCount] = useState<number>(0);
  const [tokenUsage, setTokenUsage] = useState<TokenUsage>({
    inputTokens: 0,
    outputTokens: 0,
    totalTokens: 0,
  });
  const [hasExecuted, setHasExecuted] = useState<boolean>(false);
  const [thinking, setThinking] = useState<boolean>(false);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);

  const addTokens = useCallback((tokens: number) => {
    setTokenCount((prev) => prev + tokens);
  }, []);

  const addTokenUsage = useCallback((input: number, output: number) => {
    setHasExecuted(true);
    setTokenUsage((prev) => ({
      inputTokens: prev.inputTokens + input,
      outputTokens: prev.outputTokens + output,
      totalTokens: prev.totalTokens + input + output,
    }));
    setTokenCount((prev) => prev + input + output);
  }, []);

  const resetTokenUsage = useCallback(() => {
    setHasExecuted(false);
    setTokenUsage({ inputTokens: 0, outputTokens: 0, totalTokens: 0 });
    setTokenCount(0);
  }, []);

  const contextValue = useMemo(
    () => ({
      model,
      setModel,
      tokenCount,
      setTokenCount,
      addTokens,
      tokenUsage,
      addTokenUsage,
      resetTokenUsage,
      hasExecuted,
      thinking,
      setThinking,
      isExecuting,
      setIsExecuting,
    }),
    [model, tokenCount, tokenUsage, hasExecuted, thinking, isExecuting, addTokens, addTokenUsage, resetTokenUsage]
  );

  return (
    <AgentContext.Provider value={contextValue}>
      {children}
    </AgentContext.Provider>
  );
}
