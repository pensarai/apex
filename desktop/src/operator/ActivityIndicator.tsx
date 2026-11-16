import { type OrbState, ThinkingOrb } from "thinking-orbs";
import type { OperatorActivity } from "./contract";

const states: Record<OperatorActivity, { label: string; orb: OrbState }> = {
  waiting: { label: "Waiting for model…", orb: "breathing" },
  thinking: { label: "Thinking…", orb: "solving" },
  responding: { label: "Responding…", orb: "composing" },
  working: { label: "Running tools…", orb: "working" },
};

export function ActivityIndicator({
  activity,
  modelLoading,
}: {
  activity: OperatorActivity;
  modelLoading?: string;
}) {
  const state = states[activity];
  return (
    <div
      className="op-activity"
      role="status"
      aria-live="polite"
      aria-atomic="true"
    >
      <ThinkingOrb
        state={state.orb}
        size={20}
        theme="auto"
        aria-hidden="true"
      />
      <span>{modelLoading ? "Loading model…" : state.label}</span>
    </div>
  );
}
