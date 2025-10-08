import { stepCountIs } from "ai";
import { streamResponse, type AIModel } from "../ai";
import { SYSTEM } from "./prompts";

export interface RunAgentProps {
  target: string;
  objective: string;
  model: AIModel;
}

export function runAgent(opts: RunAgentProps) {
  const { target, objective, model } = opts;
  const response = streamResponse({
    prompt: objective,
    system: SYSTEM,
    model,
    stopWhen: stepCountIs(10000),
    toolChoice: "required",
  });
}
