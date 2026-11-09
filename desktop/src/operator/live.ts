import type { OperatorMessage, OperatorSnapshot } from "./contract";

type TranscriptPatch = { from: number; messages: OperatorMessage[] };
type Agent = OperatorSnapshot["subagents"][number];
export type OperatorFrame = {
  baseRevision: number;
  state: Omit<OperatorSnapshot, "messages" | "subagents" | "skills">;
  transcript: TranscriptPatch;
  subagents: (Omit<Agent, "messages"> & { transcript: TranscriptPatch })[];
  skills?: OperatorSnapshot["skills"];
};

export function applyFrame(
  current: OperatorSnapshot,
  frame: OperatorFrame,
): OperatorSnapshot {
  const existing = new Map(current.subagents.map((a) => [a.id, a]));
  const merge = (messages: OperatorMessage[], patch: TranscriptPatch) => [
    ...messages.slice(0, patch.from),
    ...patch.messages,
  ];
  return {
    ...frame.state,
    skills: frame.skills ?? current.skills,
    messages: merge(current.messages, frame.transcript),
    subagents: frame.subagents.map(({ transcript, ...agent }) => ({
      ...agent,
      messages: merge(existing.get(agent.id)?.messages ?? [], transcript),
    })),
  };
}
