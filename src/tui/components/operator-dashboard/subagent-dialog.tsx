/**
 * Subagent Dialog
 *
 * Single dialog component managing both hub (list) and detail (conversation)
 * views internally. Follows the SkillsDialog pattern: Escape in detail view
 * navigates back to hub (with preventDefault), Escape in hub view lets the
 * DialogProvider close the dialog.
 */

import {
  useState,
  useEffect,
  useMemo,
  useRef,
  useSyncExternalStore,
} from "react";
import type { ReactNode } from "react";
import { useKeyboard } from "@opentui/react";

import { useTheme } from "../../theme";
import { useDialog } from "../../context/dialog";
import DialogLayout from "../dialog-layout";
import { AsciiSpinner } from "../shared";
import { SubagentHub, sortSessions } from "./subagent-hub";
import { SubagentDetailView } from "./subagent-detail-view";
import type { SubagentSession, SubagentStore } from "./subagent-state";

type View = { type: "hub" } | { type: "detail"; id: string };

interface SubagentDialogProps {
  store: SubagentStore;
}

function renderStatusNode(
  status: SubagentSession["status"],
  colors: ReturnType<typeof useTheme>["colors"],
): ReactNode {
  switch (status) {
    case "running":
      return <AsciiSpinner label="running" fg={colors.warning} />;
    case "completed":
      return <text fg={colors.success} content={"\u2713 completed"} />;
    case "failed":
      return <text fg={colors.error} content={"\u2717 failed"} />;
    case "cancelled":
      return <text fg={colors.textMuted} content={"\u25cb cancelled"} />;
  }
}

export default function SubagentDialog({ store }: SubagentDialogProps) {
  const { colors } = useTheme();
  const { setSize, clear } = useDialog();
  const [view, setView] = useState<View>({ type: "hub" });
  const viewRef = useRef(view);
  viewRef.current = view;

  const sessions = useSyncExternalStore(store.subscribe, store.getSnapshot);

  useEffect(() => {
    setSize(view.type === "detail" ? "xlarge" : "large");
  }, [view.type, setSize]);

  const sorted = useMemo(
    () => sortSessions(Array.from(sessions.values())),
    [sessions],
  );

  // Handle Escape for both views ourselves so execution order with the
  // DialogProvider's handler doesn't matter — we always preventDefault.
  // Detail: back to hub.  Hub: close the dialog.
  useKeyboard((key) => {
    if (key.name === "escape") {
      key.preventDefault?.();
      if (viewRef.current.type === "detail") {
        setView({ type: "hub" });
      } else {
        clear();
      }
      return;
    }
  });

  if (view.type === "detail") {
    const session = sessions.get(view.id);
    if (!session) {
      setView({ type: "hub" });
      return null;
    }
    const currentIdx = sorted.findIndex((s) => s.id === view.id);
    const safeIdx = currentIdx === -1 ? 0 : currentIdx;

    const title = (
      <box flexDirection="row" gap={1}>
        <text fg={colors.primary} content={session.name} />
        <text
          fg={colors.textMuted}
          content={`[${safeIdx + 1}/${sorted.length}]`}
        />
        {renderStatusNode(session.status, colors)}
      </box>
    );

    return (
      <DialogLayout
        title={title}
        escLabel="back"
        flushRight
        footerActions={[
          { key: "\u2190\u2192", label: "prev/next" },
          { key: "\u2191\u2193", label: "scroll" },
        ]}
      >
        <SubagentDetailView
          session={session}
          onPrev={() => {
            const prevIdx = safeIdx === 0 ? sorted.length - 1 : safeIdx - 1;
            setView({ type: "detail", id: sorted[prevIdx].id });
          }}
          onNext={() => {
            const nextIdx = safeIdx === sorted.length - 1 ? 0 : safeIdx + 1;
            setView({ type: "detail", id: sorted[nextIdx].id });
          }}
        />
      </DialogLayout>
    );
  }

  return (
    <DialogLayout
      title={`Agents (${sessions.size})`}
      flushRight
      footerActions={[
        { key: "Enter", label: "view", variant: "primary" },
        { key: "\u2191\u2193", label: "navigate" },
      ]}
    >
      <SubagentHub
        sorted={sorted}
        onSelect={(id) => setView({ type: "detail", id })}
      />
    </DialogLayout>
  );
}
