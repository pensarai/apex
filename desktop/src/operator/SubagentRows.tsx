import { Spinner } from "@pensarai/design-system/ui/spinner";
import { CheckCircle2, ChevronRight, CircleSlash, XCircle } from "lucide-react";
import { type OperatorSubagent, subagentLabel } from "./subagent-presentation";

export function SubagentRows({
  agents,
  allAgents,
  onSelect,
}: {
  agents: OperatorSubagent[];
  allAgents: OperatorSubagent[];
  onSelect: (id: string) => void;
}) {
  return (
    <div className="op-subagent-list" aria-label="Subagents">
      {agents.map((agent) => (
        <button
          key={agent.id}
          type="button"
          className="op-subagent-row"
          data-status={agent.status}
          onClick={() => onSelect(agent.id)}
        >
          <span className="op-subagent-icon" aria-hidden="true">
            {agent.status === "running" ? (
              <Spinner role={undefined} aria-label={undefined} />
            ) : agent.status === "completed" ? (
              <CheckCircle2 />
            ) : agent.status === "failed" ? (
              <XCircle />
            ) : (
              <CircleSlash />
            )}
          </span>
          <span className="op-subagent-label">
            {subagentLabel(
              agent,
              allAgents.findIndex((entry) => entry.id === agent.id),
            )}
          </span>
          <span className="op-subagent-status">
            {agent.modelLoading && agent.status === "running"
              ? "Loading model"
              : agent.status === "cancelled"
                ? "Interrupted"
                : agent.status}
          </span>
          <ChevronRight className="op-subagent-arrow" aria-hidden="true" />
        </button>
      ))}
    </div>
  );
}
