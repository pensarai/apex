import type { CreateAgentInput } from "../agents/offSecAgent";
import { runOffensiveSecurityAgent } from "./offesecAgent";

export type RunLanceInput = Omit<
  CreateAgentInput,
  | "mode"
  | "activeTools"
  | "system"
  | "extraTools"
  | "responseSchema"
  | "resolveResult"
  | "subagentSpawner"
  | "subagentId"
>;

export async function runLance(input: RunLanceInput) {
  const result = await runOffensiveSecurityAgent({
    ...input,
    mode: "lance",
    activeTools: [],
  });
  return { session: result.session, result: result.lance! };
}
