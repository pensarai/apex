/**
 * Subagent Dialog
 *
 * Single dialog component managing both hub (list) and detail (conversation)
 * views internally. Follows the SkillsDialog pattern: Escape in detail view
 * navigates back to hub (with preventDefault), Escape in hub view lets the
 * DialogProvider close the dialog.
 */

import { useState, useEffect, useMemo, useRef, type RefObject } from "react";
import { useKeyboard } from "@opentui/react";

import { useDialog } from "../../context/dialog";
import DialogLayout from "../dialog-layout";
import { SubagentHub, sortSessions } from "./subagent-hub";
import { SubagentDetailView } from "./subagent-detail-view";
import type { SubagentSession } from "./subagent-state";

type View = { type: "hub" } | { type: "detail"; id: string };

interface SubagentDialogProps {
  sessionsRef: RefObject<Map<string, SubagentSession>>;
}

export default function SubagentDialog({ sessionsRef }: SubagentDialogProps) {
  const { setSize, clear } = useDialog();
  const [view, setView] = useState<View>({ type: "hub" });
  const [, tick] = useState(0);
  const viewRef = useRef(view);
  viewRef.current = view;

  // Re-render periodically while open to reflect session changes from the ref
  useEffect(() => {
    const id = setInterval(() => tick((n) => n + 1), 500);
    return () => clearInterval(id);
  }, []);

  // Adjust dialog size when switching views
  useEffect(() => {
    setSize(view.type === "detail" ? "xlarge" : "large");
  }, [view.type, setSize]);

  const sessions = sessionsRef.current;

  const sorted = useMemo(
    () => sortSessions(Array.from(sessions.values())),
    [sessions],
  );

  // Keyboard: in detail view, Escape goes back to hub (preventDefault stops
  // DialogProvider from closing). In hub view, we don't handle Escape here —
  // SubagentHub calls onClose which calls clear(), and the DialogProvider's
  // own Escape handler also works as a fallback.
  useKeyboard((key) => {
    if (key.name === "escape" && viewRef.current.type === "detail") {
      key.preventDefault?.();
      setView({ type: "hub" });
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
            const prevIdx =
              safeIdx === 0 ? sorted.length - 1 : safeIdx - 1;
            setView({ type: "detail", id: sorted[prevIdx].id });
          }}
          onNext={() => {
            const nextIdx =
              safeIdx === sorted.length - 1 ? 0 : safeIdx + 1;
            setView({ type: "detail", id: sorted[nextIdx].id });
          }}
          onBack={() => setView({ type: "hub" })}
        />
      </DialogLayout>
    );
  }

  return (
    <DialogLayout
      title={`Agents (${sessions.size})`}
      footerActions={[
        { key: "\u2191\u2193", label: "navigate" },
        { key: "Enter", label: "view", variant: "primary" },
      ]}
    >
      <SubagentHub
        sessions={sessions}
        onSelect={(id) => setView({ type: "detail", id })}
        onClose={() => clear()}
      />
    </DialogLayout>
  );
}
