import { Spinner } from "@pensarai/design-system/ui/spinner";
import { StatusBadge } from "@pensarai/design-system/ui/status-badge";

export interface SessionStatusState {
  attention: boolean;
  running: boolean;
  unread: boolean;
}

export function SessionStatus({
  attention,
  running,
  unread,
}: SessionStatusState) {
  if (attention)
    return (
      <StatusBadge
        status="needs-input"
        tone="success"
        icon={false}
        className="session-input-badge"
      >
        Needs input
      </StatusBadge>
    );
  return (
    <span className="session-indicators">
      {running && <Spinner className="session-running" aria-label="Running" />}
      {unread && (
        <span
          className="session-unread"
          role="img"
          aria-label="Unread message"
          title="Unread message"
        />
      )}
    </span>
  );
}
