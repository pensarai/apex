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
import { useKeyboard } from "@opentui/react";

import { useDialog } from "../../context/dialog";
import DialogLayout from "../dialog-layout";
import { SubagentHub, sortSessions } from "./subagent-hub";
import { SubagentDetailView } from "./subagent-detail-view";
import type { SubagentStore } from "./subagent-state";

type View = { type: "hub" } | { type: "detail"; id: string };

interface SubagentDialogProps {
  store: SubagentStore;
}

export default function SubagentDialog({ store }: SubagentDialogProps) {
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

    return (
      <DialogLayout
        title={`Agent ${safeIdx + 1} of ${sorted.length}`}
        escLabel="back"
        footerActions={[
          { key: "\u2190\u2192", label: "prev/next" },
          { key: "\u2191\u2193", label: "scroll" },
        ]}
      >
        <SubagentDetailView
          session={session}
          index={safeIdx + 1}
          total={sorted.length}
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
      footerActions={[
        { key: "Enter", label: "view", variant: "primary" },
        { key: "\u2191\u2193", label: "navigate" },
      ]}
    >
      <SubagentHub
        sessions={sessions}
        onSelect={(id) => setView({ type: "detail", id })}
      />
    </DialogLayout>
  );
}
