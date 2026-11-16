import { Button } from "@pensarai/design-system/ui/button";
import { Input } from "@pensarai/design-system/ui/input";
import {
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarTrigger,
  useSidebar,
} from "@pensarai/design-system/ui/sidebar";
import { Plus, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";
import type { SessionRow } from "../shared";
import { api } from "./bridge";
import { SessionStatus, type SessionStatusState } from "./SessionStatus";

export interface SidebarSession extends SessionStatusState {
  tabId: string;
  sessionId?: string;
  title: string;
}

export function SessionSidebarToggle() {
  const { open, openMobile, isMobile } = useSidebar();
  return (
    <SidebarTrigger
      className="electrobun-webkit-app-region-no-drag"
      aria-label="Toggle sessions sidebar"
      aria-expanded={isMobile ? openMobile : open}
      aria-controls="session-sidebar"
      title="Toggle sessions sidebar (⌘B / Ctrl+B)"
    />
  );
}

export function SessionSidebar({
  tabs,
  selected,
  ready,
  onSelect,
  onOpen,
  onNew,
  onHistory,
}: {
  tabs: SidebarSession[];
  selected?: string;
  ready: boolean;
  onSelect: (tabId: string) => void;
  onOpen: (sessionId: string) => Promise<void>;
  onNew: () => Promise<void>;
  onHistory: () => void;
}) {
  const { isMobile, setOpenMobile } = useSidebar();
  const [history, setHistory] = useState<SessionRow[]>([]);
  const [query, setQuery] = useState("");
  const [revision, refresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [opening, setOpening] = useState(false);
  const historyKey = tabs
    .map((tab) => `${tab.sessionId}:${tab.title}:${tab.running}`)
    .join("|");
  // Refresh disk history when the open-session summary or explicit refresh changes.
  // biome-ignore lint/correctness/useExhaustiveDependencies: These are remote-data invalidation signals.
  useEffect(() => {
    let current = true;
    setLoading(true);
    void api
      .sessions()
      .then((rows) => {
        if (current) {
          setHistory(rows);
          setError("");
        }
      })
      .catch((e) => {
        if (current) setError(String(e));
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
    };
  }, [revision, historyKey]);
  useEffect(() => {
    const update = () => refresh((value) => value + 1);
    window.addEventListener("focus", update);
    return () => window.removeEventListener("focus", update);
  }, []);
  const dismissMobile = () => {
    if (isMobile) setOpenMobile(false);
  };
  const launch = async (action: () => Promise<void>) => {
    setOpening(true);
    setError("");
    try {
      await action();
      dismissMobile();
    } catch (e) {
      setError(String(e));
    } finally {
      setOpening(false);
    }
  };
  const search = query.trim().toLowerCase();
  const matches = (name: string) => name.toLowerCase().includes(search);
  const openIds = new Set(tabs.map((tab) => tab.sessionId));
  const recent = history.filter(
    (row) =>
      !openIds.has(row.id) &&
      matches([row.name, row.id, ...row.targets].join(" ")),
  );
  const openTabs = tabs.filter((tab) =>
    matches(`${tab.title} ${tab.sessionId ?? ""}`),
  );
  return (
    <>
      <SidebarHeader className="session-sidebar-header">
        <div className="session-sidebar-heading">
          <span>Sessions</span>
          <Button
            size="xs"
            variant="ghost"
            aria-label="Refresh sessions"
            disabled={loading}
            onClick={() => refresh((value) => value + 1)}
          >
            <RefreshCw size={13} />
          </Button>
        </div>
        <Button
          className="session-sidebar-new"
          size="sm"
          disabled={!ready || opening}
          onClick={() => void launch(onNew)}
        >
          <Plus size={14} /> New session
        </Button>
        <Input
          aria-label="Search sessions"
          placeholder="Search sessions…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </SidebarHeader>
      <SidebarContent>
        {error && <p role="alert">{error}</p>}
        {!!openTabs.length && (
          <SidebarGroup>
            <SidebarGroupLabel>Open</SidebarGroupLabel>
            <SidebarMenu>
              {openTabs.map((tab) => (
                <SidebarMenuItem key={tab.tabId}>
                  <SidebarMenuButton
                    className="session-sidebar-row"
                    isActive={selected === tab.tabId}
                    aria-current={selected === tab.tabId ? "page" : undefined}
                    title={tab.title}
                    onClick={() => {
                      onSelect(tab.tabId);
                      dismissMobile();
                    }}
                  >
                    <span className="session-sidebar-title">{tab.title}</span>
                    <SessionStatus {...tab} />
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroup>
        )}
        <SidebarGroup>
          <SidebarGroupLabel>Recent</SidebarGroupLabel>
          <SidebarMenu>
            {recent.slice(0, 40).map((row) => (
              <SidebarMenuItem key={row.id}>
                <SidebarMenuButton
                  className="session-sidebar-row"
                  title={row.name}
                  disabled={opening || !ready}
                  onClick={() => void launch(() => onOpen(row.id))}
                >
                  <span className="session-sidebar-title">{row.name}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            ))}
          </SidebarMenu>
          {!recent.length && (
            <p className="session-sidebar-empty">
              {loading
                ? "Loading sessions…"
                : search
                  ? "No matching sessions."
                  : "No saved sessions."}
            </p>
          )}
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            onHistory();
            dismissMobile();
          }}
        >
          View all sessions
        </Button>
      </SidebarFooter>
    </>
  );
}
