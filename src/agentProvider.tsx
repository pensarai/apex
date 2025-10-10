import { createContext, useContext, useState } from "react";
import type { ModelInfo } from "../core/ai";

interface AgentContextValue {
  model: ModelInfo;
  setModel: (model: ModelInfo) => void;
  tokenCount: number;
  setTokenCount: (tokenCount: number) => void;
  thinking: boolean;
  setThinking: (thinking: boolean) => void;
}

const AgentContext = createContext<AgentContextValue | null>(null);

export function useAgent() {
  const context = useContext(AgentContext);
  if (!context) {
    throw new Error("useAgent must be used within AgentProvider");
  }
  return context;
}
