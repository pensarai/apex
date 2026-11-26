import type {
  OperatorActivity,
  OperatorMessage,
  OperatorSnapshot,
} from "./contract";

export type OperatorSubagent = OperatorSnapshot["subagents"][number];

export function subagentLabel(agent: OperatorSubagent, index: number): string {
  return agent.name && agent.name !== agent.id
    ? agent.name
    : `Subagent ${index + 1}`;
}

export function subagentActivity(
  agent: OperatorSubagent,
): OperatorActivity | undefined {
  if (agent.status !== "running") return undefined;
  if (agent.modelLoading) return "waiting";
  const last = agent.messages.at(-1);
  if (
    last?.role === "tool" &&
    ["pending", "streaming", "running"].includes(last.status ?? "")
  )
    return "working";
  return last?.role === "assistant" && last.content ? "responding" : "thinking";
}

export function groupSubagents(
  messages: OperatorMessage[],
  agents: OperatorSubagent[],
) {
  const allCalls = new Set(
    [...messages, ...agents.flatMap((agent) => agent.messages)].flatMap(
      (message) => (message.toolCallId ? [message.toolCallId] : []),
    ),
  );
  const byTool = new Map<string, OperatorSubagent[]>();
  for (const agent of agents) {
    if (agent.parentToolCallId && allCalls.has(agent.parentToolCallId)) {
      byTool.set(agent.parentToolCallId, [
        ...(byTool.get(agent.parentToolCallId) ?? []),
        agent,
      ]);
    }
  }
  return { byTool };
}
