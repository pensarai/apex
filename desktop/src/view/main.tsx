import { PensarMark } from "@pensarai/design-system/logos";
import { Button } from "@pensarai/design-system/ui/button";
import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import type { PentestInput } from "../pentest/contract";
import { useDesktopAppearance } from "../settings/appearance";
import type { SettingsTab } from "../settings/contract";
import type { RunLocation } from "../shared";
import { api } from "./bridge";
import type { TerminalLaunch } from "./Terminal";
import "./style.css";

const Skills = lazy(() => import("./Skills"));
const Operator = lazy(() => import("../operator/Operator"));
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
  const [page, navigate] = useState<Page>("Sessions");
  const [skills, showSkills] = useState<{ slug?: string }>();
  const [runLocation, setRunLocation] = useState<RunLocation>({});
  const [pentestInitial, setPentestInitial] = useState<Partial<PentestInput>>();
  const [settings, setSettings] = useState<SettingsTab>();
  const openSettings = (tab: SettingsTab = "Providers") => setSettings(tab);
  const [resumeId, setResumeId] = useState<string>();
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
  const exited = useCallback((message: string) => {
    setTerminal(undefined);
    setExitMessage(message);
  }, []);
  const resume = (id: string) => {
    setPentestInitial(undefined);
    setResumeId(id);
    navigate("Operator");
  };
  const selectPage = (p: Page) => {
    setPentestInitial(undefined);
    setRunLocation({});
    setResumeId(undefined);
    navigate(p);
  };
  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <PensarMark size={28} />
          <span>Apex</span>
        </div>
        <nav aria-label="Workspace">
          {pages.map((p) => (
            <button
              key={p}
              type="button"
              aria-current={p === page ? "page" : undefined}
              disabled={!workspace?.accepted}
              onClick={() => selectPage(p)}
            >
              {p}
            </button>
          ))}
        </nav>
        {workspace && (
          <footer>
            <Button
              variant="ghost"
              disabled={!workspace.accepted}
              onClick={() => showSkills({})}
            >
              Skills
            </Button>
            <Button
              variant="ghost"
              disabled={!workspace.accepted}
              onClick={() => openSettings()}
            >
              Settings
            </Button>
            <small>Working directory</small>
            <button
              type="button"
              className="folder"
              disabled={!workspace.accepted || !!terminal}
              title={workspace.cwd}
              onClick={async () => {
                try {
                  const cwd = await api.chooseFolder();
                  setWorkspace({ ...workspace, cwd });
                } catch (e) {
                  setError(String(e));
                }
              }}
            >
              {workspace.cwd} <span>⌄</span>
            </button>
            <span className="version">Apex {workspace.version}</span>
          </footer>
        )}
      </aside>
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
              Apex is for authorized security testing. You must have explicit
              written permission to test the systems, networks, or applications
              in scope.
            </p>
            <p>
              By continuing, you agree to test only systems you own or have
              permission to test, comply with applicable laws, avoid harm or
              service disruption, and document and report findings responsibly.
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
            fallback={<p className="empty">Opening {page.toLowerCase()}…</p>}
          >
            {page === "Operator" && (
              <Operator
                initialSessionId={resumeId}
                onSettings={openSettings}
                onSkills={(slug) => showSkills({ slug })}
                onPentest={async (command) => {
                  const result = await api.pentestCommand({ command });
                  if (result.kind === "started") resume(result.sessionId);
                  else {
                    setPentestInitial(result.initial);
                    setResumeId(undefined);
                    navigate("Pentest");
                  }
                }}
                onSessions={(id) => (id ? resume(id) : selectPage("Sessions"))}
                onRuns={async (command) => {
                  const location = await api.openRunsCommand({ command });
                  selectPage("Recorded runs");
                  setRunLocation(location);
                }}
                onExit={() => api.quit().catch((e) => setError(String(e)))}
              />
            )}
            {page === "Pentest" && (
              <Pentest
                initial={pentestInitial}
                cwd={workspace.cwd}
                onSettings={openSettings}
                onStarted={() => selectPage("Operator")}
              />
            )}
            {page === "Sessions" && (
              <Sessions
                resume={resume}
                startOperator={() => selectPage("Operator")}
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
  );
}
const root = document.getElementById("root");
if (root) createRoot(root).render(<App />);
