import { createContext, useContext, useState, type ReactNode } from "react";
import { AVAILABLE_MODELS, type ModelInfo } from "../core/ai";

interface AgentContextValue {
  model: ModelInfo;
  setModel: (model: ModelInfo) => void;
  tokenCount: number;
  setTokenCount: (tokenCount: number) => void;
  addTokens: (tokens: number) => void;
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
  const [thinking, setThinking] = useState<boolean>(false);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);

  const addTokens = (tokens: number) => {
    setTokenCount((prev) => prev + tokens);
  };

  return (
    <AgentContext.Provider
      value={{
        model,
        setModel,
        tokenCount,
        setTokenCount,
        addTokens,
        thinking,
        setThinking,
        isExecuting,
        setIsExecuting,
      }}
    >
      {children}
    </AgentContext.Provider>
  );
}
