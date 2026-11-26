import { Button } from "@pensarai/design-system/ui/button";
import { ChevronRight, Target } from "lucide-react";
import type { OperatorSnapshot } from "./contract";

export function GoalStatus({
  state,
  busy,
  onEnd,
  onResume,
}: {
  state: OperatorSnapshot;
  busy: boolean;
  onEnd: () => void;
  onResume: () => void;
}) {
  const goal = state.goal;
  if (!goal) return null;
  const active = goal.status === "active";
  const status =
    active && state.goalsEnabled === false
      ? "Disabled"
      : active && state.goalPaused
        ? "Paused"
        : active && state.status === "waiting"
          ? "Needs input"
          : {
              active: "Active",
              complete: "Complete",
              blocked: "Blocked",
              cancelled: "Ended",
            }[goal.status];
  return (
    <details className="op-goal">
      <summary>
        <ChevronRight size={12} className="op-goal-chevron" />
        <Target size={14} />
        <span className="op-goal-objective">{goal.objective}</span>
        <span className="op-goal-status">{status}</span>
        <span>
          {goal.rounds}/{goal.maxRounds}
        </span>
      </summary>
      <div className="op-goal-detail">
        <p>{goal.objective}</p>
        {goal.completion && (
          <>
            <p>{goal.completion.summary}</p>
            <ul>
              {goal.completion.evidence.map((ref) => (
                <li key={ref}>
                  <code>{ref}</code>
                </li>
              ))}
            </ul>
          </>
        )}
        {goal.detail && <p>{goal.detail}</p>}
        {!goal.detail && goal.reason === "rounds" && (
          <p>Round limit reached.</p>
        )}
        {!goal.detail && goal.reason === "no_progress" && (
          <p>Stopped after repeated rounds without tool progress.</p>
        )}
        {active && (
          <div className="actions">
            {state.goalPaused && state.status === "idle" && (
              <Button
                size="xs"
                variant="default"
                disabled={busy || state.goalsEnabled === false || state.lance}
                onClick={onResume}
              >
                Resume goal
              </Button>
            )}
            <Button size="xs" variant="ghost" disabled={busy} onClick={onEnd}>
              End goal
            </Button>
          </div>
        )}
      </div>
    </details>
  );
}
