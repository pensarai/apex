import { Button } from "@pensarai/design-system/ui/button";
import { Square, Terminal, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { BackgroundJobState } from "../../../src/core/eventBus";
import "./processes.css";

export function Processes({
  processes,
  busy,
  onCancel,
  onClose,
}: {
  processes: BackgroundJobState[];
  busy: boolean;
  onCancel: (jobId: string) => void;
  onClose: () => void;
}) {
  const closeButton = useRef<HTMLButtonElement>(null);
  const [selectedId, setSelectedId] = useState<string | undefined>(
    () =>
      (processes.find((job) => job.status === "running") ?? processes.at(-1))
        ?.jobId,
  );
  const selected =
    processes.find((job) => job.jobId === selectedId) ??
    processes.find((job) => job.status === "running") ??
    processes.at(-1);
  useEffect(() => {
    closeButton.current?.focus();
  }, []);
  return (
    <aside
      className="op-processes"
      aria-label="Processes"
      onKeyDown={(event) => {
        if (event.key === "Escape" && !event.defaultPrevented) {
          event.preventDefault();
          onClose();
        }
      }}
    >
      <div className="op-process-picker">
        <nav className="op-process-list" aria-label="Command processes">
          {processes.map((job) => (
            <Button
              key={job.jobId}
              variant="ghost"
              className="op-process-row"
              aria-pressed={job.jobId === selected?.jobId}
              onClick={() => setSelectedId(job.jobId)}
            >
              <Terminal size={14} aria-hidden="true" />
              <span>{job.command}</span>
              <span className="op-process-state">{processStatus(job)}</span>
            </Button>
          ))}
        </nav>
        <Button
          ref={closeButton}
          size="icon-xs"
          variant="ghost"
          aria-label="Close processes sidebar"
          onClick={onClose}
        >
          <X size={14} />
        </Button>
      </div>
      {selected ? (
        <section className="op-process-detail" aria-label="Selected process">
          <div className="op-process-terminal-command">
            <time dateTime={new Date(selected.startedAt).toISOString()}>
              {new Date(selected.startedAt).toLocaleTimeString()}
            </time>
            {selected.status === "running" && !selected.subagentId && (
              <Button
                size="icon-xs"
                variant="ghost"
                disabled={busy}
                aria-label="Cancel process"
                title="Cancel process"
                onClick={() => onCancel(selected.jobId)}
              >
                <Square size={12} />
              </Button>
            )}
          </div>
          <pre className="op-process-command">
            <span aria-hidden="true">{selected.toolName ? "> " : "$ "}</span>
            {selected.toolName && `${selected.toolName}: `}
            {selected.command}
          </pre>
          <pre className="op-process-output">
            {selected.stdout}
            {selected.stderr && (
              <span className="op-process-stderr">
                {selected.stdout && !selected.stdout.endsWith("\n") ? "\n" : ""}
                {selected.stderr}
              </span>
            )}
          </pre>
          {selected.error && (
            <p className="op-process-error">{selected.error}</p>
          )}
        </section>
      ) : (
        <p className="op-process-empty">
          No background processes in this turn.
        </p>
      )}
    </aside>
  );
}

function processStatus(job: BackgroundJobState) {
  if (job.status === "running") return "Running";
  if (job.verdict === "accepted") return "Accepted";
  if (job.verdict === "rejected") return "Rejected";
  if (job.verdict === "duplicate") return "Duplicate";
  if (job.exitCode === 130) return "Cancelled";
  if (job.exitCode === 124) return "Timed out";
  return job.success === false ||
    job.error ||
    (job.exitCode !== undefined && job.exitCode !== 0)
    ? "Failed"
    : "Completed";
}
