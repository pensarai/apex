import { PensarMark } from "@pensarai/design-system/logos";
import { Button } from "@pensarai/design-system/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@pensarai/design-system/ui/dropdown-menu";
import { SidebarProvider } from "@pensarai/design-system/ui/sidebar";
import { Minus, Square, X } from "lucide-react";
import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { createRoot } from "react-dom/client";
import type { PentestInput } from "../pentest/contract";
import { useDesktopAppearance } from "../settings/appearance";
import type { SettingsTab } from "../settings/contract";
import type { RunLocation } from "../shared";
import { api } from "./bridge";
import { SessionSidebarFrame } from "./SessionSidebar";
import type { SessionWorkspaceHandle } from "./SessionWorkspace";
import type { TerminalLaunch } from "./Terminal";
import "./style.css";

const Skills = lazy(() => import("./Skills"));
const SessionWorkspace = lazy(() => import("./SessionWorkspace"));
const Pentest = lazy(() => import("../pentest/Pentest"));
const Settings = lazy(() => import("../settings/Settings"));
const Sessions = lazy(() =>
  import("./Sessions").then((m) => ({ default: m.Sessions })),
);
const Runs = lazy(() => import("./Runs").then((m) => ({ default: m.Runs })));
const Terminal = lazy(() =>
  import("./Terminal").then((m) => ({ default: m.Terminal })),
);

const pages = [
  "Operator",
  "Pentest",
  "Sessions",
  "Recorded runs",
  "Terminal",
] as const;
type Page = (typeof pages)[number];

function App() {
  const [page, navigate] = useState<Page>("Operator");
  const [menuOpen, setMenuOpen] = useState(false);
  const [skills, showSkills] = useState<{ slug?: string }>();
  const [runLocation, setRunLocation] = useState<RunLocation>({});
  const [pentestInitial, setPentestInitial] = useState<Partial<PentestInput>>();
  const [settings, setSettings] = useState<SettingsTab>();
  const openSettings = (tab: SettingsTab = "Providers") => setSettings(tab);
  const sessions = useRef<SessionWorkspaceHandle>(null);
  const [tabBar, setTabBar] = useState<HTMLDivElement | null>(null);
  const [sidebar, setSidebar] = useState<HTMLDivElement | null>(null);
  const activateOperator = useCallback(() => navigate("Operator"), []);
  const [workspace, setWorkspace] =
    useState<Awaited<ReturnType<typeof api.workspace>>>();
  const [error, setError] = useState("");
  const [terminal, setTerminal] = useState<TerminalLaunch>();
  const [exitMessage, setExitMessage] = useState("");
  useDesktopAppearance();
  const load = useCallback(() => {
    setError("");
    void api
      .workspace()
      .then((state) => {
        setWorkspace(state);
        if (state.accepted && !state.hasProvider) setSettings("Providers");
      })
      .catch((e) => setError(String(e)));
  }, []);
  useEffect(load, [load]);
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (
        (event.metaKey || event.ctrlKey) &&
        event.key.toLowerCase() === "k" &&
        !event.isComposing
      ) {
        event.preventDefault();
        setMenuOpen((open) => !open);
      }
    };
    window.addEventListener("keydown", keydown);
    return () => window.removeEventListener("keydown", keydown);
  }, []);
  const chooseFolder = async () => {
    if (!workspace) return;
    try {
      const cwd = await api.chooseFolder();
      setWorkspace({ ...workspace, cwd });
    } catch (e) {
      setError(String(e));
    }
  };
  const exited = useCallback((message: string) => {
    setTerminal(undefined);
    setExitMessage(message);
  }, []);
  const resume = (id: string) => {
    setPentestInitial(undefined);
    void sessions.current?.open(id).catch((e) => setError(String(e)));
  };
  const selectPage = (p: Page) => {
    setPentestInitial(undefined);
    setRunLocation({});
    navigate(p);
  };
  return (
    <SidebarProvider className="desktop-sidebar-provider">
      <div className="shell">
        <div className="app-bar electrobun-webkit-app-region-drag">
          {navigator.platform.includes("Mac") ? (
            <div className="app-native-controls" aria-hidden="true" />
          ) : (
            <div className="app-window-controls electrobun-webkit-app-region-no-drag">
              {(
                [
                  { action: "close", label: "Close window", Icon: X },
                  { action: "minimize", label: "Minimize window", Icon: Minus },
                  {
                    action: "toggle-maximize",
                    label: "Maximize or restore window",
                    Icon: Square,
                  },
                ] as const
              ).map(({ action, label, Icon }) => (
                <Button
                  key={action}
                  size="sm"
                  variant="ghost"
                  aria-label={label}
                  title={label}
                  onClick={() =>
                    void api
                      .windowAction({ action })
                      .catch((e) => setError(String(e)))
                  }
                >
                  <Icon size={14} aria-hidden="true" />
                </Button>
              ))}
            </div>
          )}
          <DropdownMenu open={menuOpen} onOpenChange={setMenuOpen}>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                className="app-menu-trigger electrobun-webkit-app-region-no-drag"
                aria-label="Apex menu"
                title="Apex menu (⌘K / Ctrl+K)"
              >
                <PensarMark size={18} fill="currentColor" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="app-menu">
              <DropdownMenuItem
                disabled={!workspace?.accepted}
                onSelect={() =>
                  void sessions.current
                    ?.newSession()
                    .catch((e) => setError(String(e)))
                }
              >
                New session
                <span className="menu-current">
                  {navigator.platform.includes("Mac") ? "⌘N" : "Ctrl+N"}
                </span>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuLabel>Workspace</DropdownMenuLabel>
              {pages.map((p) => (
                <DropdownMenuItem
                  key={p}
                  disabled={!workspace?.accepted}
                  aria-current={page === p ? "page" : undefined}
                  onSelect={() => selectPage(p)}
                >
                  {p}
                  {page === p && (
                    <span className="menu-current" aria-hidden="true">
                      •
                    </span>
                  )}
                </DropdownMenuItem>
              ))}
              <DropdownMenuSeparator />
              <DropdownMenuItem
                disabled={!workspace?.accepted}
                onSelect={() => showSkills({})}
              >
                Skills
              </DropdownMenuItem>
              <DropdownMenuItem
                disabled={!workspace?.accepted}
                onSelect={() => openSettings()}
              >
                Settings
              </DropdownMenuItem>
              <DropdownMenuItem
                disabled={!workspace?.accepted || !!terminal}
                onSelect={() => void chooseFolder()}
              >
                Change working directory…
              </DropdownMenuItem>
              {workspace && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuLabel className="app-menu-version">
                    Apex {workspace.version}
                  </DropdownMenuLabel>
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
          {page !== "Operator" && <span className="app-location">{page}</span>}
          <div className="app-session-bar" ref={setTabBar} />
        </div>
        <div className="app-body">
          {workspace?.accepted && <SessionSidebarFrame onMount={setSidebar} />}
          <main>
            {error && (
              <div role="alert">
                {error}{" "}
                <Button size="sm" onClick={load}>
                  Retry
                </Button>
              </div>
            )}
            {!workspace ? (
              <p className="empty">Opening workspace…</p>
            ) : !workspace.accepted ? (
              <section className="disclosure">
                <PensarMark size={40} />
                <h1>Responsible use</h1>
                <p>
                  Apex is for authorized security testing. You must have
                  explicit written permission to test the systems, networks, or
                  applications in scope.
                </p>
                <p>
                  By continuing, you agree to test only systems you own or have
                  permission to test, comply with applicable laws, avoid harm or
                  service disruption, and document and report findings
                  responsibly.
                </p>
                <Button
                  variant="constructive"
                  onClick={async () => {
                    try {
                      await api.accept();
                      setWorkspace({ ...workspace, accepted: true });
                      if (!workspace.hasProvider) setSettings("Providers");
                    } catch (e) {
                      setError(String(e));
                    }
                  }}
                >
                  Accept and continue
                </Button>
              </section>
            ) : (
              <Suspense
                fallback={
                  <p className="empty">Opening {page.toLowerCase()}…</p>
                }
              >
                <SessionWorkspace
                  ref={sessions}
                  active={page === "Operator"}
                  onActivate={activateOperator}
                  tabBar={tabBar}
                  sidebar={sidebar}
                  canChooseFolder={!terminal}
                  onDirectoryChanged={(cwd) =>
                    setWorkspace((current) =>
                      current ? { ...current, cwd } : current,
                    )
                  }
                  onSettings={openSettings}
                  onSkills={(slug) => showSkills({ slug })}
                  onPentest={async (command) => {
                    const result = await api.pentestCommand({ command });
                    if (result.kind === "started") resume(result.sessionId);
                    else {
                      setPentestInitial(result.initial);
                      navigate("Pentest");
                    }
                  }}
                  onSessions={(id) =>
                    id ? resume(id) : selectPage("Sessions")
                  }
                  onRuns={async (command) => {
                    const location = await api.openRunsCommand({ command });
                    selectPage("Recorded runs");
                    setRunLocation(location);
                  }}
                  onExit={() => api.quit().catch((e) => setError(String(e)))}
                />
                {page === "Pentest" && (
                  <Pentest
                    initial={pentestInitial}
                    cwd={workspace.cwd}
                    onSettings={openSettings}
                    onStarted={resume}
                  />
                )}
                {page === "Sessions" && (
                  <Sessions
                    resume={resume}
                    startOperator={() =>
                      void sessions.current
                        ?.newSession()
                        .catch((e) => setError(String(e)))
                    }
                    startPentest={() => selectPage("Pentest")}
                  />
                )}
                {page === "Recorded runs" && (
                  <Runs cwd={workspace.cwd} location={runLocation} />
                )}
                {page === "Terminal" && (
                  <header>
                    <div>
                      <h1>Terminal</h1>
                      <p>Run the Apex TUI in the selected working directory.</p>
                    </div>
                    {!terminal && (
                      <Button
                        variant="constructive"
                        onClick={() => {
                          setExitMessage("");
                          setTerminal({});
                        }}
                      >
                        Start terminal
                      </Button>
                    )}
                  </header>
                )}
                {terminal && (
                  <Terminal
                    launch={terminal}
                    visible={page === "Terminal"}
                    onExit={exited}
                  />
                )}
                {page === "Terminal" && !terminal && (
                  <div className="empty">
                    <h2>{exitMessage || "Terminal ready"}</h2>
                    <p>
                      Use <code>/help</code> for the list of terminal commands.
                    </p>
                  </div>
                )}
                {skills && (
                  <Skills
                    initialSlug={skills.slug}
                    close={() => showSkills(undefined)}
                  />
                )}
                {settings && (
                  <Settings
                    initialTab={settings}
                    onClose={() => setSettings(undefined)}
                  />
                )}
              </Suspense>
            )}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
const root = document.getElementById("root");
if (root) createRoot(root).render(<App />);
