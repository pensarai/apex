import { Button } from "@pensarai/design-system/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@pensarai/design-system/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@pensarai/design-system/ui/dropdown-menu";
import { Tabs, TabsList, TabsTrigger } from "@pensarai/design-system/ui/tabs";
import {
  type ComponentProps,
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useReducer,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { createOperatorClient, type OperatorClient } from "../operator/client";
import type {
  OperatorLaunch,
  OperatorSnapshot,
  OperatorTab,
} from "../operator/contract";
import Operator from "../operator/Operator";
import { api } from "./bridge";
import { SessionSidebar } from "./SessionSidebar";
import { SessionStatus } from "./SessionStatus";
import { type SessionLayout, sessionLayout } from "./session-layout";
import {
  latestSessionReply,
  needsSessionInput,
  sessionUnread,
} from "./session-status";
import "./session-workspace.css";

export interface SessionWorkspaceHandle {
  open: (sessionId?: string) => Promise<void>;
  newSession: (launch?: OperatorLaunch) => Promise<void>;
}

type Callbacks = Pick<
  ComponentProps<typeof Operator>,
  "onSettings" | "onPentest" | "onSessions" | "onSkills" | "onRuns" | "onExit"
>;
type Props = Callbacks & {
  active: boolean;
  onActivate: () => void;
  tabBar: HTMLElement | null;
  sidebar: HTMLElement | null;
  canChooseFolder: boolean;
  onDirectoryChanged: (cwd: string) => void;
};
type Tab = OperatorTab & {
  client: OperatorClient;
  title: string;
  attention: boolean;
  unread: boolean;
};

function title(snapshot: OperatorSnapshot) {
  return (
    snapshot.name ||
    snapshot.messages
      .find((m) => m.role === "user")
      ?.content.trim()
      .slice(0, 64) ||
    "New session"
  );
}

function SessionPane({
  tab,
  focused,
  displayed,
  side,
  onFocus,
  onSnapshot,
  onNewSession,
  chooseFolder,
  callbacks,
}: {
  tab: Tab;
  focused: boolean;
  displayed: boolean;
  side: "left" | "right";
  onFocus: (id: string) => void;
  onSnapshot: (id: string, snapshot: OperatorSnapshot) => void;
  onNewSession: (launch?: OperatorLaunch) => Promise<void>;
  chooseFolder?: (id: string) => Promise<void>;
  callbacks: Callbacks;
}) {
  const update = useCallback(
    (snapshot: OperatorSnapshot) => onSnapshot(tab.tabId, snapshot),
    [onSnapshot, tab.tabId],
  );
  return (
    <section
      className="session-pane"
      hidden={!displayed}
      data-focused={focused}
      style={{ gridColumn: side === "right" ? 3 : 1 }}
      role="tabpanel"
      id={`session-panel-${tab.tabId}`}
      aria-labelledby={`session-tab-${tab.tabId}`}
      onPointerDownCapture={() => onFocus(tab.tabId)}
      onFocusCapture={() => onFocus(tab.tabId)}
    >
      <Operator
        {...callbacks}
        client={tab.client}
        initialSnapshot={tab.snapshot}
        visible={displayed}
        focused={focused}
        cwd={tab.cwd}
        onNewSession={onNewSession}
        onSnapshot={update}
        onChooseFolder={
          chooseFolder && !tab.snapshot.sessionId
            ? () => chooseFolder(tab.tabId)
            : undefined
        }
      />
    </section>
  );
}

export default forwardRef<SessionWorkspaceHandle, Props>(
  function SessionWorkspace(
    {
      active,
      onActivate,
      tabBar,
      sidebar,
      canChooseFolder,
      onDirectoryChanged,
      ...callbacks
    },
    ref,
  ) {
    const [tabs, setTabs] = useState<Tab[]>([]);
    const [layout, dispatch] = useReducer(sessionLayout, { order: [] });
    const [ready, setReady] = useState(false);
    const [windowFocused, setWindowFocused] = useState(() =>
      document.hasFocus(),
    );
    const [retry, setRetry] = useState(0);
    const [error, setError] = useState("");
    const [dragging, setDragging] = useState<string>();
    const [dropTarget, setDropTarget] = useState<{
      id: string;
      after: boolean;
    }>();
    const [closing, setClosing] = useState<string>();
    const [closeBusy, setCloseBusy] = useState(false);
    const [ratio, setRatio] = useState(50);
    const grid = useRef<HTMLDivElement>(null);
    const dragOrigin = useRef<SessionLayout>(undefined);
    const initialization = useRef<Promise<OperatorTab[]>>(undefined);
    const tabsRef = useRef(tabs);
    const replies = useRef(new Map<string, string>());
    tabsRef.current = tabs;
    const reading = useRef<string | undefined>(undefined);
    reading.current = active && windowFocused ? layout.focused : undefined;
    useEffect(() => {
      const focus = () =>
        setWindowFocused(
          document.hasFocus() && document.visibilityState === "visible",
        );
      window.addEventListener("focus", focus);
      window.addEventListener("blur", focus);
      document.addEventListener("visibilitychange", focus);
      return () => {
        window.removeEventListener("focus", focus);
        window.removeEventListener("blur", focus);
        document.removeEventListener("visibilitychange", focus);
      };
    }, []);
    useEffect(() => {
      if (!active || !windowFocused || !layout.focused) return;
      setTabs((current) =>
        current.some((tab) => tab.tabId === layout.focused && tab.unread)
          ? current.map((tab) =>
              tab.tabId === layout.focused ? { ...tab, unread: false } : tab,
            )
          : current,
      );
    }, [active, windowFocused, layout.focused]);

    const register = useCallback((descriptor: OperatorTab) => {
      if (!replies.current.has(descriptor.tabId))
        replies.current.set(
          descriptor.tabId,
          latestSessionReply(descriptor.snapshot),
        );
      setTabs((current) =>
        current.some((tab) => tab.tabId === descriptor.tabId)
          ? current
          : [
              ...current,
              {
                ...descriptor,
                client: createOperatorClient(descriptor.tabId),
                title: title(descriptor.snapshot),
                attention: needsSessionInput(descriptor.snapshot),
                unread: false,
              },
            ],
      );
      dispatch({ type: "open", id: descriptor.tabId });
    }, []);
    useEffect(() => {
      let mounted = true;
      if (retry) initialization.current = undefined;
      initialization.current ??= api
        .operatorTabs()
        .then(async (open) =>
          open.length ? open : [await api.operatorOpen({})],
        );
      void initialization.current
        .then((open) => {
          if (!mounted) return;
          for (const tab of open) register(tab);
          setReady(true);
        })
        .catch((e) => {
          if (mounted) setError(String(e));
        });
      return () => {
        mounted = false;
      };
    }, [register, retry]);

    const update = useCallback((id: string, snapshot: OperatorSnapshot) => {
      const reply = latestSessionReply(snapshot);
      const previousReply = replies.current.get(id) ?? reply;
      replies.current.set(id, reply);
      setTabs((current) => {
        const tab = current.find((item) => item.tabId === id);
        if (!tab) return current;
        const nextTitle = title(snapshot);
        const attention = needsSessionInput(snapshot);
        const unread = sessionUnread(
          previousReply,
          reply,
          tab.unread,
          reading.current === id,
        );
        if (
          tab.title === nextTitle &&
          tab.attention === attention &&
          tab.unread === unread &&
          tab.snapshot.status === snapshot.status &&
          tab.snapshot.sessionId === snapshot.sessionId
        )
          return current;
        return current.map((item) =>
          item === tab
            ? { ...tab, title: nextTitle, attention, snapshot, unread }
            : item,
        );
      });
    }, []);
    const open = useCallback(
      async (sessionId?: string) => {
        const tab = await api.operatorOpen({ sessionId });
        register(tab);
        onActivate();
      },
      [register, onActivate],
    );
    const newSession = useCallback(
      async (launch?: OperatorLaunch) => {
        const tab = await api.operatorOpen({});
        register(tab);
        onActivate();
        if (launch)
          update(
            tab.tabId,
            await createOperatorClient(tab.tabId).operatorStart(launch),
          );
      },
      [register, update, onActivate],
    );
    useImperativeHandle(ref, () => ({ open, newSession }), [open, newSession]);
    const select = useCallback((id: string) => {
      dispatch({ type: "select", id });
    }, []);
    const close = useCallback(async (id: string, stop = false) => {
      const tab = tabsRef.current.find((item) => item.tabId === id);
      if (!tab) return;
      if (!stop && tab.snapshot.status !== "idle") {
        setError("");
        setClosing(id);
        return;
      }
      setCloseBusy(true);
      setError("");
      try {
        await api.operatorClose({ tabId: id, stop });
        replies.current.delete(id);
        setTabs((current) => current.filter((item) => item.tabId !== id));
        dispatch({ type: "close", id });
        setClosing(undefined);
      } catch (e) {
        setError(String(e));
      } finally {
        setCloseBusy(false);
      }
    }, []);
    useEffect(() => {
      const command = (type: "new" | "close") => {
        if (!ready || closeBusy || closing) return;
        if (type === "new") void newSession().catch((e) => setError(String(e)));
        else if (active && layout.focused) void close(layout.focused);
      };
      const keydown = (event: KeyboardEvent) => {
        if (
          !(event.metaKey || event.ctrlKey) ||
          event.altKey ||
          event.shiftKey ||
          event.isComposing ||
          event.repeat
        )
          return;
        const key = event.key.toLowerCase();
        if (key !== "n" && key !== "w") return;
        if (key === "w" && !active) return;
        event.preventDefault();
        command(key === "n" ? "new" : "close");
      };
      const nativeCommand = (event: Event) =>
        command((event as CustomEvent<{ type: "new" | "close" }>).detail.type);
      window.addEventListener("keydown", keydown);
      window.addEventListener("apex:session-command", nativeCommand);
      return () => {
        window.removeEventListener("keydown", keydown);
        window.removeEventListener("apex:session-command", nativeCommand);
      };
    }, [ready, newSession, close, layout.focused, active, closeBusy, closing]);
    useEffect(() => {
      if (layout.focused)
        document
          .getElementById(`session-tab-${layout.focused}`)
          ?.scrollIntoView({
            block: "nearest",
            inline: "nearest",
          });
    }, [layout.focused]);
    useEffect(() => {
      if (!dragging) return;
      const cancel = () => {
        setDragging(undefined);
        setDropTarget(undefined);
      };
      window.addEventListener("dragend", cancel);
      window.addEventListener("drop", cancel);
      return () => {
        window.removeEventListener("dragend", cancel);
        window.removeEventListener("drop", cancel);
      };
    }, [dragging]);

    const chooseFolder = async (id: string) => {
      try {
        const cwd = await api.chooseFolder();
        await api.operatorSetDirectory({ tabId: id, cwd });
        setTabs((current) =>
          current.map((tab) => (tab.tabId === id ? { ...tab, cwd } : tab)),
        );
        onDirectoryChanged(cwd);
      } catch (e) {
        setError(String(e));
      }
    };
    const dock = (id: string, side: "left" | "right") => {
      const origin = dragging === id ? dragOrigin.current : undefined;
      const beside =
        origin &&
        [
          side === "left" ? origin.secondary : origin.primary,
          origin.primary,
          origin.secondary,
        ].find((other) => other && other !== id);
      dispatch({ type: "dock", id, side, beside });
      onActivate();
    };
    const focusedIndex = layout.order.indexOf(layout.focused ?? "");
    const move = (offset: number) => {
      const target = layout.order[focusedIndex + offset];
      if (layout.focused && target)
        dispatch({
          type: "reorder",
          id: layout.focused,
          target,
          after: offset > 0,
        });
    };
    const shortcut = navigator.platform.includes("Mac") ? "⌘" : "Ctrl+";
    const tabStrip = (
      <>
        <TabsList
          className="session-tabs electrobun-webkit-app-region-no-drag"
          variant="line"
          aria-label="Open sessions"
        >
          {layout.order.map((id) => {
            const tab = tabs.find((item) => item.tabId === id);
            if (!tab) return null;
            return (
              <div
                key={id}
                className="session-tab"
                data-focused={active && layout.focused === id}
                data-visible={id === layout.primary || id === layout.secondary}
                data-drop={
                  dropTarget?.id === id
                    ? dropTarget.after
                      ? "after"
                      : "before"
                    : undefined
                }
                draggable
                onPointerDownCapture={() => {
                  dragOrigin.current = layout;
                }}
                onDragStart={(event) => {
                  event.dataTransfer.setData("application/x-apex-session", id);
                  event.dataTransfer.effectAllowed = "move";
                  setDragging(id);
                }}
                onDragOver={(event) => {
                  if (!dragging) return;
                  event.preventDefault();
                  event.dataTransfer.dropEffect = "move";
                  const rect = event.currentTarget.getBoundingClientRect();
                  setDropTarget({
                    id,
                    after: event.clientX > rect.left + rect.width / 2,
                  });
                }}
                onDragLeave={() => setDropTarget(undefined)}
                onDrop={(event) => {
                  if (!dragging) return;
                  event.preventDefault();
                  const rect = event.currentTarget.getBoundingClientRect();
                  dispatch({
                    type: "reorder",
                    id: dragging,
                    target: id,
                    after: event.clientX > rect.left + rect.width / 2,
                  });
                  setDragging(undefined);
                  setDropTarget(undefined);
                }}
              >
                <TabsTrigger
                  value={id}
                  id={`session-tab-${id}`}
                  aria-controls={`session-panel-${id}`}
                  title={tab.title}
                  className="session-tab-trigger"
                  onClick={onActivate}
                >
                  <SessionStatus
                    attention={tab.attention}
                    running={tab.snapshot.status !== "idle"}
                    unread={tab.unread}
                  />
                  <span className="session-tab-title">{tab.title}</span>
                </TabsTrigger>
                <Button
                  variant="ghost"
                  size="xs"
                  className="session-tab-close"
                  aria-label={`Close ${tab.title}`}
                  title={`Close session (${shortcut}W)`}
                  disabled={closeBusy}
                  onClick={() => void close(id)}
                >
                  ×
                </Button>
              </div>
            );
          })}
        </TabsList>
        <Button
          variant="ghost"
          size="sm"
          className="session-new electrobun-webkit-app-region-no-drag"
          aria-label="New session"
          title={`New session (${shortcut}N)`}
          disabled={!ready}
          onClick={() => void newSession().catch((e) => setError(String(e)))}
        >
          +
        </Button>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="electrobun-webkit-app-region-no-drag"
              aria-label="Arrange sessions"
              title="Arrange sessions"
              disabled={!layout.focused}
            >
              ⋯
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="app-menu">
            <DropdownMenuItem
              disabled={layout.order.length < 2}
              onSelect={() => layout.focused && dock(layout.focused, "left")}
            >
              Dock session left
            </DropdownMenuItem>
            <DropdownMenuItem
              disabled={layout.order.length < 2}
              onSelect={() => layout.focused && dock(layout.focused, "right")}
            >
              Dock session right
            </DropdownMenuItem>
            <DropdownMenuItem
              disabled={!layout.secondary}
              onSelect={() => dispatch({ type: "single" })}
            >
              Single pane
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              disabled={focusedIndex <= 0}
              onSelect={() => move(-1)}
            >
              Move tab left
            </DropdownMenuItem>
            <DropdownMenuItem
              disabled={
                focusedIndex < 0 || focusedIndex >= layout.order.length - 1
              }
              onSelect={() => move(1)}
            >
              Move tab right
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              disabled={!layout.focused || closeBusy}
              onSelect={() => layout.focused && void close(layout.focused)}
            >
              Close session <span className="menu-current">{shortcut}W</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </>
    );
    return (
      <Tabs
        className="session-workspace"
        value={layout.focused ?? ""}
        onValueChange={(id) => {
          select(id);
          onActivate();
        }}
        hidden={!active}
      >
        {tabBar && createPortal(tabStrip, tabBar)}
        {sidebar &&
          createPortal(
            <SessionSidebar
              tabs={layout.order.flatMap((id) => {
                const tab = tabs.find((item) => item.tabId === id);
                return tab
                  ? [
                      {
                        tabId: tab.tabId,
                        sessionId: tab.snapshot.sessionId,
                        title: tab.title,
                        attention: tab.attention,
                        running: tab.snapshot.status !== "idle",
                        unread: tab.unread,
                      },
                    ]
                  : [];
              })}
              selected={active ? layout.focused : undefined}
              ready={ready}
              onSelect={(id) => {
                select(id);
                onActivate();
              }}
              onOpen={open}
              onNew={newSession}
              onHistory={() => callbacks.onSessions?.()}
            />,
            sidebar,
          )}
        {error && !closing && (
          <div role="alert">
            {error}
            {ready ? (
              <Button size="xs" variant="ghost" onClick={() => setError("")}>
                Dismiss
              </Button>
            ) : (
              <Button
                size="xs"
                onClick={() => {
                  initialization.current = undefined;
                  setError("");
                  setRetry((value) => value + 1);
                }}
              >
                Retry
              </Button>
            )}
          </div>
        )}
        {!ready && !error && <p className="empty">Opening sessions…</p>}
        {ready && !tabs.length && (
          <div className="session-empty">
            <p>No sessions open.</p>
            <Button
              onClick={() =>
                void newSession().catch((e) => setError(String(e)))
              }
            >
              New session
            </Button>
          </div>
        )}
        <div
          ref={grid}
          className="session-grid"
          data-split={!!layout.secondary}
          style={{
            gridTemplateColumns: layout.secondary
              ? `minmax(0, ${ratio}fr) 5px minmax(0, ${100 - ratio}fr)`
              : "minmax(0, 1fr)",
          }}
        >
          {/* One parent keeps drafts and scroll intact when panes move. */}
          {tabs.map((tab) => (
            <SessionPane
              key={tab.tabId}
              tab={tab}
              focused={active && layout.focused === tab.tabId}
              displayed={
                active &&
                (layout.primary === tab.tabId || layout.secondary === tab.tabId)
              }
              side={layout.secondary === tab.tabId ? "right" : "left"}
              onFocus={select}
              onSnapshot={update}
              onNewSession={newSession}
              chooseFolder={canChooseFolder ? chooseFolder : undefined}
              callbacks={callbacks}
            />
          ))}
          {layout.secondary && (
            <div
              role="separator"
              tabIndex={0}
              aria-label="Resize session panes"
              aria-controls={`session-panel-${layout.primary} session-panel-${layout.secondary}`}
              aria-orientation="vertical"
              aria-valuemin={25}
              aria-valuemax={75}
              aria-valuenow={Math.round(ratio)}
              className="session-divider"
              onPointerDown={(event) => {
                event.preventDefault();
                event.currentTarget.setPointerCapture(event.pointerId);
              }}
              onPointerMove={(event) => {
                if (
                  !event.currentTarget.hasPointerCapture(event.pointerId) ||
                  !grid.current
                )
                  return;
                const rect = grid.current.getBoundingClientRect();
                setRatio(
                  Math.max(
                    25,
                    Math.min(
                      75,
                      ((event.clientX - rect.left) / rect.width) * 100,
                    ),
                  ),
                );
              }}
              onPointerUp={(event) =>
                event.currentTarget.releasePointerCapture(event.pointerId)
              }
              onDoubleClick={() => setRatio(50)}
              onKeyDown={(event) => {
                if (
                  !["ArrowLeft", "ArrowRight", "Home", "End"].includes(
                    event.key,
                  )
                )
                  return;
                event.preventDefault();
                setRatio((current) =>
                  event.key === "Home"
                    ? 25
                    : event.key === "End"
                      ? 75
                      : Math.max(
                          25,
                          Math.min(
                            75,
                            current + (event.key === "ArrowLeft" ? -5 : 5),
                          ),
                        ),
                );
              }}
            />
          )}
          {dragging && active && layout.order.length > 1 && (
            <div className="session-dock-targets">
              {(["left", "right"] as const).map((side) => (
                <div
                  key={side}
                  className="session-dock-target"
                  onDragOver={(event) => {
                    event.preventDefault();
                    event.dataTransfer.dropEffect = "move";
                  }}
                  onDrop={(event) => {
                    event.preventDefault();
                    dock(dragging, side);
                    setDragging(undefined);
                  }}
                >
                  <span>Dock {side}</span>
                </div>
              ))}
            </div>
          )}
        </div>
        <Dialog
          open={!!closing}
          onOpenChange={(value) => {
            if (!value && !closeBusy) setClosing(undefined);
          }}
        >
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Stop and close this session?</DialogTitle>
              <DialogDescription>
                This session is still active or waiting for your input. Closing
                stops its work. Saved messages and artifacts remain in Sessions.
              </DialogDescription>
            </DialogHeader>
            {error && <div role="alert">{error}</div>}
            <DialogFooter>
              <Button
                disabled={closeBusy}
                variant="ghost"
                onClick={() => setClosing(undefined)}
              >
                Keep open
              </Button>
              <Button
                disabled={closeBusy}
                onClick={() => closing && void close(closing, true)}
              >
                {closeBusy ? "Stopping…" : "Stop and close"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </Tabs>
    );
  },
);
