import { stepCountIs, type StreamTextResult, type ToolSet } from "ai";
import { streamResponse, type AIModel } from "../ai";
import { SYSTEM } from "./prompts";

export interface RunAgentProps {
  target: string;
  objective: string;
  model: AIModel;
}

export function runAgent(
  opts: RunAgentProps
): StreamTextResult<ToolSet, never> {
  const { target, objective, model } = opts;
  return streamResponse({
    prompt: objective,
    system: SYSTEM,
    model,
    stopWhen: stepCountIs(10000),
    toolChoice: "required",
  });
}
