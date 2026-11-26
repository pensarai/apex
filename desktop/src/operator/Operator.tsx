import { PensarMark } from "@pensarai/design-system/logos";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@pensarai/design-system/ui/breadcrumb";
import { Button } from "@pensarai/design-system/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@pensarai/design-system/ui/dialog";
import { Input } from "@pensarai/design-system/ui/input";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@pensarai/design-system/ui/resizable";
import {
  ArrowUp,
  File as FileIcon,
  Globe,
  Network,
  Paperclip,
  ShieldAlert,
  Square,
  X,
} from "lucide-react";
import {
  Fragment,
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
} from "react";
import { Browser } from "../browser/Browser";
import { type BrowserLink, BrowserLinkContext } from "../browser/links";
import { NativeViews } from "../browser/NativeViews";
import { runAppearanceCommand } from "../settings/appearance";
import type { SettingsSnapshot, SettingsTab } from "../settings/contract";
import { api } from "../view/bridge";
import { AttackSurface } from "./AttackSurface";
import { encodeAttachments, validateAttachmentSizes } from "./attachments";
import { CommandInput } from "./CommandInput";
import type { OperatorClient } from "./client";
import type {
  OperatorAction,
  OperatorLaunch,
  OperatorSnapshot,
} from "./contract";
import { GoalStatus } from "./GoalStatus";
import { Issues } from "./Issues";
import { applyFrame, type OperatorFrame } from "./live";
import { ModelPicker } from "./ModelPicker";
import { Processes } from "./Processes";
import { Questions } from "./Questions";
import { OperatorSetup } from "./Setup";
import { SlashMenu } from "./SlashMenu";
import { parseSlashInput, slashEntries } from "./slash-commands";
import { subagentActivity, subagentLabel } from "./subagent-presentation";
import { hasSurfaceToolCall, surfaceReveal } from "./surface-reveal";
import { ToolPicker } from "./ToolPicker";
import { Transcript } from "./Transcript";
import { runningCommandId } from "./turn-controls";
import "./operator.css";

type Panel = "Overview" | "Plan" | "Headers" | "Skills" | "Help";
const panels: Panel[] = ["Overview", "Plan", "Headers", "Skills", "Help"];
interface Props {
  cwd?: string;
  onChooseFolder?: () => Promise<void>;
  client: OperatorClient;
  initialSnapshot: OperatorSnapshot;
  visible: boolean;
  focused?: boolean;
  onNewSession: (launch?: OperatorLaunch) => Promise<void>;
  onSnapshot: (snapshot: OperatorSnapshot) => void;
  onSettings?: (tab?: SettingsTab) => void;
  onPentest?: (command: string) => Promise<void>;
  onSessions?: (id?: string) => void;
  onSkills?: (slug?: string) => void;
  onRuns?: (command: string) => Promise<void>;
  onExit?: () => void;
}

export default function OperatorSessionView({
  cwd,
  onChooseFolder,
  client,
  initialSnapshot,
  visible,
  focused: isFocused = visible,
  onNewSession,
  onSnapshot,
  onSettings,
  onPentest,
  onRuns,
  onExit,
  onSessions,
  onSkills,
}: Props) {
  const [modelSettings, setModelSettings] =
    useState<Pick<SettingsSnapshot, "models" | "selected">>();
  const [state, setState] = useState(initialSnapshot);
  const [panel, setPanel] = useState<Panel>("Overview");
  const [setupOpen, setSetupOpen] = useState(false);
  const [inspecting, setInspecting] = useState(false);
  const [draftMode, setDraftMode] =
    useState<OperatorSnapshot["mode"]>("manual");
  const mode = state?.sessionId ? state.mode : draftMode;
  const ready = !!state;
  const [prefill, setPrefill] = useState<OperatorLaunch>();
  const [formKey, setFormKey] = useState(0);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [text, setText] = useState("");
  const [skills, setSkills] = useState(initialSnapshot.skills);
  const [slashIndex, setSlashIndex] = useState(0);
  const [slashDismissed, setSlashDismissed] = useState(false);
  const slashId = useId();
  const entries = slashEntries(text, skills);
  const slashOpen = !slashDismissed && /^\/[^\s]*$/.test(text);
  const selectedSlash =
    entries[Math.min(slashIndex, Math.max(0, entries.length - 1))]?.slug;
  const insertSlash = (slug: string) => {
    setText(`/${slug} `);
    setSlashDismissed(true);
    input.current?.focus();
  };
  // biome-ignore lint/correctness/useExhaustiveDependencies: Changing the working directory changes the project skill catalog.
  useEffect(() => {
    let cancelled = false;
    void client
      .operatorSkills()
      .then((next) => {
        if (!cancelled) setSkills(next);
      })
      .catch((failure) => {
        if (!cancelled) setError(`Skills could not be loaded: ${failure}`);
      });
    return () => {
      cancelled = true;
    };
  }, [client, cwd]);
  const [attachments, setAttachments] = useState<{ id: string; file: File }[]>(
    [],
  );
  const [draggingFiles, setDraggingFiles] = useState(false);
  const dragDepth = useRef(0);
  const fileInput = useRef<HTMLInputElement>(null);
  const [agentPath, setAgentPath] = useState<string[]>([]);
  const [header, setHeader] = useState("");
  const [verbose, setVerbose] = useState(false);
  const [toolsOpen, setToolsOpen] = useState(false);
  const [modelsOpen, setModelsOpen] = useState(false);
  const [browserViewport, setBrowserViewport] = useState<HTMLDivElement | null>(
    null,
  );
  const [browserOpen, setBrowserOpen] = useState(false);
  const browserTrigger = useRef<HTMLButtonElement>(null);
  const [surfaceOpen, setSurfaceOpen] = useState(false);
  const [processesOpen, setProcessesOpen] = useState(false);
  const [issuesOpen, setIssuesOpen] = useState(false);
  const issuesTrigger = useRef<HTMLButtonElement>(null);
  const processTrigger = useRef<HTMLButtonElement>(null);
  const processes = state.processes ?? [];
  const runningProcesses = processes.filter(
    (job) => job.status === "running",
  ).length;
  const sidebarOpen = surfaceOpen || processesOpen || issuesOpen || browserOpen;
  const surfaceActivity = hasSurfaceToolCall(state);
  useEffect(() => {
    if (
      state.sessionId &&
      surfaceActivity &&
      surfaceReveal.claim(state.sessionId)
    )
      setSurfaceOpen(!processesOpen && !issuesOpen && !browserOpen);
  }, [
    state.sessionId,
    surfaceActivity,
    processesOpen,
    issuesOpen,
    browserOpen,
  ]);
  const surfaceId = useId();
  const surfaceWidth = useRef(50);
  const surfaceTrigger = useRef<HTMLButtonElement>(null);
  const input = useRef<HTMLTextAreaElement>(null);
  const page = useRef<HTMLDivElement>(null);
  const latest = useRef(initialSnapshot);
  const focused = useRef(isFocused);
  focused.current = isFocused;
  const reportSnapshot = useRef(onSnapshot);
  reportSnapshot.current = onSnapshot;
  const apply = useCallback((next: OperatorSnapshot) => {
    if (!latest.current || next.revision >= latest.current.revision) {
      latest.current = next;
      setState(next);
      reportSnapshot.current(next);
    }
  }, []);
  useEffect(() => {
    let active = true;
    const key = crypto.randomUUID();
    const refresh = () =>
      client
        .operatorWatch({ key })
        .then((s) => {
          if (active) apply(s);
        })
        .catch((e) => {
          if (active) setError(String(e));
        });
    const receive = (frame: OperatorFrame) => {
      const current = latest.current;
      if (current && frame.state.revision <= current.revision) return;
      if (!current || current.revision < frame.baseRevision) {
        void refresh();
        return;
      }
      apply(applyFrame(current, frame));
    };
    const unsubscribe = client.subscribe(receive);
    setError("");
    void refresh();
    return () => {
      active = false;
      unsubscribe();
      void client.operatorUnwatch({ key }).catch(console.error);
    };
  }, [client, apply]);
  useEffect(() => {
    let active = true;
    const update = (settings: SettingsSnapshot) => {
      if (active)
        setModelSettings({
          models: settings.models,
          selected: settings.selected,
        });
    };
    const changed = (event: Event) =>
      update((event as CustomEvent<SettingsSnapshot>).detail);
    void api
      .desktopSettings()
      .then(update)
      .catch((e) => {
        if (active) setError(String(e));
      });
    window.addEventListener("apex:settings", changed);
    return () => {
      active = false;
      window.removeEventListener("apex:settings", changed);
    };
  }, []);
  async function perform(fn: () => Promise<OperatorSnapshot>) {
    setBusy(true);
    setError("");
    try {
      apply(await fn());
      return true;
    } catch (e) {
      setError(String(e));
      return false;
    } finally {
      setBusy(false);
    }
  }
  function action(command: OperatorAction) {
    const sessionId = state?.sessionId;
    if (!sessionId) return Promise.resolve(false);
    return perform(() => client.operatorAction({ sessionId, action: command }));
  }
  async function newChat(clearAttachments = true) {
    await onNewSession();
    setText("");
    if (clearAttachments) setAttachments([]);
  }
  function addAttachments(files: File[]) {
    if (!files.length || busy) return;
    try {
      validateAttachmentSizes([
        ...attachments.map(({ file }) => file),
        ...files,
      ]);
      setAttachments((previous) => [
        ...previous,
        ...files.map((file) => ({ id: crypto.randomUUID(), file })),
      ]);
      setError("");
      input.current?.focus();
    } catch (error) {
      setError(String(error));
    }
  }
  function openPanel(next: Panel) {
    setPanel(next);
    setInspecting(true);
  }
  const modeLocked =
    busy || !!state?.questions || !!state?.reviewPlan || !!state?.lance;
  function cycleMode() {
    if (modeLocked) return;
    const next =
      mode === "manual" ? "auto" : mode === "auto" ? "plan" : "manual";
    if (state?.sessionId) void action({ type: "mode", mode: next });
    else setDraftMode(next);
  }
  useEffect(() => {
    if (
      isFocused &&
      ready &&
      !setupOpen &&
      !sidebarOpen &&
      !document.activeElement?.matches('[role="tab"][aria-selected="true"]') &&
      !page.current?.contains(document.activeElement)
    )
      input.current?.focus();
  }, [isFocused, ready, setupOpen, sidebarOpen]);
  useEffect(() => {
    if (!isFocused) {
      setSetupOpen(false);
      setToolsOpen(false);
      setModelsOpen(false);
    }
  }, [isFocused]);
  const submit = async () => {
    const value = text.trim();
    const sessionId = state.sessionId;
    if ((!value && !attachments.length) || busy) return;
    let consumedAttachments = !value.startsWith("/");
    const encodedAttachments = () =>
      encodeAttachments(attachments.map(({ file }) => file));
    if (value.startsWith("/")) {
      setError("");
      try {
        const { command: cmd, arguments: args, rest } = parseSlashInput(value);
        const noArgs = [
          "new",
          "plan",
          "tools",
          "help",
          "models",
          "effort",
          "providers",
          "login",
          "credits",
          "advanced",
          "open-session",
          "exit",
        ];
        if (noArgs.includes(cmd) && args.length)
          throw new Error(`/${cmd} takes no arguments.`);
        if (["skills", "resume"].includes(cmd) && args.length > 1)
          throw new Error(`/${cmd} accepts at most one argument.`);
        if (
          !state?.sessionId &&
          ["headers", "tools", "plan", "open-session"].includes(cmd)
        )
          throw new Error(
            `Start or resume an operator session to use /${cmd}.`,
          );
        switch (cmd) {
          case "goal":
            if (
              !(await perform(async () => {
                const next = await client.operatorGoal({
                  command: rest,
                  mode,
                  attachments: await encodedAttachments(),
                });
                consumedAttachments =
                  !!next.goal && next.goal.id !== state.goal?.id;
                return next;
              }))
            )
              return;
            break;
          case "pentest":
            if (!onPentest) throw new Error("Open Pentest from the sidebar.");
            setText("");
            await onPentest(value);
            break;
          case "runs":
            if (!onRuns)
              throw new Error("Open Recorded runs from the sidebar.");
            await onRuns(value);
            break;
          case "new":
            await newChat(false);
            break;
          case "operator":
          case "threat-model":
          case "prompt-injection": {
            if (cmd === "operator" && !args.length && !attachments.length) {
              await newChat();
              break;
            }
            setPrefill(await client.operatorArguments({ command: value }));
            setFormKey((n) => n + 1);
            setSetupOpen(true);
            return;
          }
          case "resume":
            if (!onSessions) throw new Error("Open Sessions from the sidebar.");
            onSessions(args[0]);
            break;
          case "tools":
            setToolsOpen(true);
            break;
          case "models":
            setModelsOpen(true);
            break;
          case "effort":
            onSettings?.("Models");
            break;
          case "providers":
            onSettings?.("Providers");
            break;
          case "login":
          case "credits":
            onSettings?.("Account");
            break;
          case "themes":
          case "obfuscate":
            if (cmd === "themes" && !args.length) onSettings?.("Appearance");
            else
              await runAppearanceCommand(
                cmd === "obfuscate" ? "obfuscate" : "theme",
                args,
              );
            break;
          case "advanced":
            onSettings?.("Advanced");
            break;
          case "help":
            openPanel("Help");
            break;
          case "headers":
            openPanel("Headers");
            if (!(await action({ type: "headers", command: value }))) return;
            break;
          case "plan":
            openPanel("Plan");
            break;
          case "skills":
            if (onSkills) onSkills(args[0]);
            else openPanel("Skills");
            break;
          case "open-session":
            if (!(await action({ type: "open-folder" }))) return;
            break;
          case "exit":
            if (onExit) onExit();
            else
              throw new Error("Close the Apex window to quit the desktop app.");
            break;
          default:
            if (!skills.some((skill) => skill.slug === cmd))
              throw new Error(
                "Unknown operator command. Enter /help for available commands.",
              );
            if (!sessionId) {
              if (
                !(await perform(async () =>
                  client.operatorStart({
                    attachments: await encodedAttachments(),
                    skill: cmd,
                    skillArguments: args.filter((arg) => arg !== "--autopilot"),
                    mode: args.includes("--autopilot") ? "auto" : draftMode,
                  }),
                ))
              )
                return;
              consumedAttachments = true;
              break;
            }
            if (
              !(await perform(async () =>
                client.operatorAction({
                  sessionId,
                  action: {
                    type: "skill",
                    attachments: await encodedAttachments(),
                    slug: cmd,
                    autopilot: args.includes("--autopilot"),
                    arguments: args.filter((a) => a !== "--autopilot"),
                  },
                }),
              ))
            )
              return;
            consumedAttachments = true;
        }
      } catch (e) {
        setError(String(e));
        return;
      }
    } else if (!sessionId) {
      if (
        !(await perform(async () =>
          client.operatorStart({
            prompt: value,
            mode: draftMode,
            attachments: await encodeAttachments(
              attachments.map(({ file }) => file),
            ),
          }),
        ))
      )
        return;
    } else if (
      !(await perform(async () =>
        client.operatorAction({
          sessionId,
          action: {
            type: "send",
            text: value,
            attachments: await encodeAttachments(
              attachments.map(({ file }) => file),
            ),
          },
        }),
      ))
    )
      return;
    setText("");
    if (consumedAttachments) setAttachments([]);
    if (focused.current) input.current?.focus();
  };
  const active = !!state && state.status !== "idle";
  const path = agentPath.flatMap((id) => {
    const agent = state.subagents.find((entry) => entry.id === id);
    return agent ? [agent] : [];
  });
  const current = path.at(-1);
  const openSubagent = (id: string) => {
    setAgentPath((previous) =>
      previous.includes(id)
        ? previous.slice(0, previous.indexOf(id) + 1)
        : [...previous, id],
    );
    setInspecting(false);
  };
  const openBrowserLink = useCallback(
    async (link: BrowserLink) => {
      setSurfaceOpen(false);
      setIssuesOpen(false);
      setProcessesOpen(false);
      setBrowserOpen(true);
      await client.operatorBrowserInput({ input: link });
    },
    [client],
  );
  const cancelCommandId =
    state.status === "running" ? runningCommandId(state.messages) : undefined;
  return (
    <BrowserLinkContext.Provider value={openBrowserLink}>
      <div className="op-page" ref={page}>
        <NativeViews
          client={client}
          visible={visible && browserOpen}
          viewport={browserViewport}
        />
        {state && (
          <header>
            <div>
              <h1 className="op-session-title">
                {state?.sessionId ? state.name || "Operator" : "New session"}
              </h1>
            </div>
            <div className="actions">
              <Button
                size="sm"
                ref={browserTrigger}
                disabled={busy}
                aria-expanded={browserOpen}
                aria-controls={browserOpen ? surfaceId : undefined}
                onClick={() =>
                  void (async () => {
                    if (
                      !state.sessionId &&
                      !(await perform(() => client.operatorStart({ mode })))
                    )
                      return;
                    setSurfaceOpen(false);
                    setIssuesOpen(false);
                    setProcessesOpen(false);
                    setBrowserOpen((open) => !open);
                  })()
                }
              >
                <Globe size={14} aria-hidden="true" /> Browser
              </Button>
              {state.sessionId && (
                <Button
                  size="sm"
                  ref={surfaceTrigger}
                  aria-expanded={surfaceOpen}
                  aria-controls={surfaceOpen ? surfaceId : undefined}
                  onClick={() => {
                    if (state.sessionId)
                      surfaceReveal.markShown(state.sessionId);
                    setProcessesOpen(false);
                    setIssuesOpen(false);
                    setBrowserOpen(false);
                    setSurfaceOpen((open) => !open);
                  }}
                >
                  <Network size={14} aria-hidden="true" />
                  Attack surface
                </Button>
              )}
              {state.sessionId && (
                <Button
                  size="sm"
                  ref={issuesTrigger}
                  aria-expanded={issuesOpen}
                  aria-controls={issuesOpen ? surfaceId : undefined}
                  onClick={() => {
                    setSurfaceOpen(false);
                    setProcessesOpen(false);
                    setBrowserOpen(false);
                    setIssuesOpen((open) => !open);
                  }}
                >
                  <ShieldAlert size={14} aria-hidden="true" />
                  Issues
                </Button>
              )}
              <Button
                size="sm"
                aria-pressed={inspecting}
                onClick={() => setInspecting(!inspecting)}
              >
                {inspecting ? "Hide details" : "Details"}
              </Button>
            </div>
          </header>
        )}
        {error && <p role="alert">{error}</p>}
        {!state ? (
          <p className="empty">
            {error ? "Unable to open operator." : "Opening operator…"}
          </p>
        ) : (
          <>
            <ResizablePanelGroup
              orientation="horizontal"
              className="op-session-content"
              onLayoutChanged={(layout) => {
                if (sidebarOpen && layout[surfaceId] !== undefined)
                  surfaceWidth.current = layout[surfaceId];
              }}
            >
              <ResizablePanel
                id={`${surfaceId}-conversation`}
                minSize="25%"
                defaultSize={`${100 - surfaceWidth.current}%`}
                className="op-conversation-panel"
              >
                <div
                  className={`op-body${inspecting ? " op-with-inspector" : ""}`}
                >
                  <div
                    className={`op-chat${state.sessionId ? "" : " op-chat-empty"}`}
                  >
                    {current && (
                      <div className="op-agent-context">
                        <Breadcrumb aria-label="Conversation path">
                          <BreadcrumbList>
                            <BreadcrumbItem>
                              <BreadcrumbLink asChild>
                                <button
                                  type="button"
                                  onClick={() => setAgentPath([])}
                                >
                                  Operator
                                </button>
                              </BreadcrumbLink>
                            </BreadcrumbItem>
                            {path.map((agent, index) => (
                              <Fragment key={agent.id}>
                                <BreadcrumbSeparator />
                                <BreadcrumbItem>
                                  {index === path.length - 1 ? (
                                    <BreadcrumbPage>
                                      {subagentLabel(
                                        agent,
                                        state.subagents.indexOf(agent),
                                      )}
                                    </BreadcrumbPage>
                                  ) : (
                                    <BreadcrumbLink asChild>
                                      <button
                                        type="button"
                                        onClick={() =>
                                          setAgentPath(
                                            path
                                              .slice(0, index + 1)
                                              .map((entry) => entry.id),
                                          )
                                        }
                                      >
                                        {subagentLabel(
                                          agent,
                                          state.subagents.indexOf(agent),
                                        )}
                                      </button>
                                    </BreadcrumbLink>
                                  )}
                                </BreadcrumbItem>
                              </Fragment>
                            ))}
                          </BreadcrumbList>
                        </Breadcrumb>
                        <span className="op-agent-view-status">
                          {current.status === "cancelled"
                            ? "Interrupted"
                            : current.status}{" "}
                          · Read-only
                        </span>
                        {current.input != null && (
                          <details className="op-agent-objective">
                            <summary>Objective</summary>
                            <pre>{JSON.stringify(current.input, null, 2)}</pre>
                          </details>
                        )}
                      </div>
                    )}
                    {state.sessionId ? (
                      <>
                        <div className="op-transcript-view" hidden={!!current}>
                          <Transcript
                            key={state.sessionId}
                            screenshot={client.operatorScreenshot}
                            visible={visible && !current}
                            messages={state.messages}
                            sessionId={state.sessionId}
                            activity={state.activity}
                            modelLoading={state.modelLoading}
                            subagents={state.subagents}
                            onSelectSubagent={openSubagent}
                            cancelCommandId={cancelCommandId}
                            commandBusy={busy}
                            onCancelCommand={(toolCallId) =>
                              void action({
                                type: "cancel-command",
                                toolCallId,
                              })
                            }
                            verbose={verbose}
                          />
                        </div>
                        {path.map((agent) => (
                          <div
                            className="op-transcript-view"
                            key={agent.id}
                            hidden={agent.id !== current?.id}
                          >
                            <Transcript
                              screenshot={client.operatorScreenshot}
                              visible={visible && agent.id === current?.id}
                              messages={agent.messages}
                              sessionId={state.sessionId ?? ""}
                              agentId={agent.id}
                              activity={subagentActivity(agent)}
                              modelLoading={agent.modelLoading ?? undefined}
                              subagents={state.subagents}
                              onSelectSubagent={openSubagent}
                              verbose={verbose}
                            />
                          </div>
                        ))}
                      </>
                    ) : (
                      <div className="op-welcome">
                        <PensarMark size={80} fill="currentColor" />
                        <h1>Apex</h1>
                      </div>
                    )}
                    {state.error && <p role="alert">{state.error}</p>}
                    <div className="op-decisions">
                      {state.approvals.map((a) => (
                        <section key={a.id} className="op-review">
                          <h3>Approve {a.toolName}?</h3>
                          {a.reasoning && <p>{a.reasoning}</p>}
                          <pre>{JSON.stringify(a.args, null, 2)}</pre>
                          <div className="actions">
                            {(["approve", "deny", "auto"] as const).map(
                              (decision) => (
                                <Button
                                  key={decision}
                                  size="sm"
                                  disabled={busy}
                                  onClick={() =>
                                    action({
                                      type: "approval",
                                      id: a.id,
                                      decision,
                                    })
                                  }
                                >
                                  {decision === "approve"
                                    ? "Approve"
                                    : decision === "deny"
                                      ? "Deny"
                                      : "Approve and switch to automatic"}
                                </Button>
                              ),
                            )}
                          </div>
                        </section>
                      ))}
                      {state.questions && (
                        <Questions
                          key={state.questions.toolCallId}
                          id={state.questions.toolCallId}
                          questions={state.questions.questions}
                          submit={action}
                          disabled={busy || state.status !== "waiting"}
                        />
                      )}
                      {state.reviewPlan && (
                        <div className="op-review">
                          <h3>Review the proposed plan</h3>
                          <pre>{state.plan ?? "Reading plan…"}</pre>
                          <div className="actions">
                            <Button
                              disabled={busy || state.status !== "waiting"}
                              variant="constructive"
                              onClick={() =>
                                action({ type: "plan", approve: true })
                              }
                            >
                              Approve plan
                            </Button>
                            <Button
                              disabled={busy || state.status !== "waiting"}
                              onClick={() =>
                                action({ type: "plan", approve: false })
                              }
                            >
                              Request changes
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>
                    {!current && runningProcesses > 0 && (
                      <div className="op-process-bar">
                        <Button
                          size="xs"
                          className="op-process-pill"
                          ref={processTrigger}
                          aria-expanded={processesOpen}
                          aria-controls={processesOpen ? surfaceId : undefined}
                          onClick={() => {
                            setSurfaceOpen(false);
                            setIssuesOpen(false);
                            setBrowserOpen(false);
                            setProcessesOpen((open) => !open);
                          }}
                        >
                          <span className="op-process-dot" aria-hidden="true" />
                          {runningProcesses} running{" "}
                          {runningProcesses === 1 ? "process" : "processes"}
                        </Button>
                      </div>
                    )}
                    {!current && (
                      <div
                        className={`op-compose${draggingFiles ? " op-compose-dragging" : ""}`}
                        role="group"
                        aria-label="Message composer"
                        onDragEnter={(event) => {
                          if (!event.dataTransfer.types.includes("Files"))
                            return;
                          event.preventDefault();
                          dragDepth.current++;
                          setDraggingFiles(true);
                        }}
                        onDragOver={(event) => {
                          if (!event.dataTransfer.types.includes("Files"))
                            return;
                          event.preventDefault();
                          event.dataTransfer.dropEffect = busy
                            ? "none"
                            : "copy";
                        }}
                        onDragLeave={(event) => {
                          if (!event.dataTransfer.types.includes("Files"))
                            return;
                          event.preventDefault();
                          if (--dragDepth.current <= 0) {
                            dragDepth.current = 0;
                            setDraggingFiles(false);
                          }
                        }}
                        onDrop={(event) => {
                          if (!event.dataTransfer.types.includes("Files"))
                            return;
                          event.preventDefault();
                          event.stopPropagation();
                          dragDepth.current = 0;
                          setDraggingFiles(false);
                          if (
                            Array.from(event.dataTransfer.items).some(
                              (item) => item.webkitGetAsEntry?.()?.isDirectory,
                            )
                          ) {
                            setError("Drop individual files, not folders.");
                            return;
                          }
                          addAttachments(Array.from(event.dataTransfer.files));
                        }}
                      >
                        <GoalStatus
                          state={state}
                          busy={busy}
                          onEnd={() =>
                            void action({ type: "goal", command: "clear" })
                          }
                          onResume={() => void action({ type: "resume-goal" })}
                        />
                        {slashOpen && (
                          <SlashMenu
                            id={slashId}
                            entries={entries}
                            selected={selectedSlash}
                            onSelect={insertSlash}
                          />
                        )}
                        {draggingFiles && (
                          <div className="op-attachment-hint">
                            Drop files to attach
                          </div>
                        )}
                        {!!attachments.length && (
                          <ul
                            className="op-attachments"
                            aria-label="Attached files"
                          >
                            {attachments.map(({ id, file }) => (
                              <li
                                key={id}
                                className="op-attachment"
                                title={file.name}
                              >
                                <FileIcon size={14} aria-hidden="true" />
                                <span>{file.name}</span>
                                <Button
                                  variant="ghost"
                                  size="icon-sm"
                                  disabled={busy}
                                  aria-label={`Remove ${file.name}`}
                                  onClick={() =>
                                    setAttachments((previous) =>
                                      previous.filter(
                                        (entry) => entry.id !== id,
                                      ),
                                    )
                                  }
                                >
                                  <X size={12} aria-hidden="true" />
                                </Button>
                              </li>
                            ))}
                          </ul>
                        )}
                        {state.queue.map((q) => (
                          <div key={q.id} className="op-queued">
                            <span>{q.text}</span>
                            <Button
                              size="xs"
                              disabled={busy}
                              onClick={() =>
                                action({
                                  type: "queue",
                                  id: q.id,
                                  operation: "send-now",
                                })
                              }
                            >
                              Send now
                            </Button>
                            <Button
                              size="xs"
                              disabled={busy}
                              onClick={async () => {
                                if (
                                  await action({
                                    type: "queue",
                                    id: q.id,
                                    operation: "remove",
                                  })
                                )
                                  setText(q.text);
                              }}
                            >
                              Edit
                            </Button>
                            <Button
                              size="xs"
                              disabled={busy}
                              onClick={() =>
                                action({
                                  type: "queue",
                                  id: q.id,
                                  operation: "remove",
                                })
                              }
                            >
                              Remove
                            </Button>
                          </div>
                        ))}
                        <CommandInput
                          skills={skills}
                          ref={input}
                          aria-label="Operator message"
                          value={text}
                          disabled={busy}
                          aria-expanded={slashOpen}
                          aria-controls={slashOpen ? slashId : undefined}
                          aria-activedescendant={
                            slashOpen && selectedSlash
                              ? `${slashId}-${selectedSlash}`
                              : undefined
                          }
                          aria-autocomplete="list"
                          onBlur={() => setSlashDismissed(true)}
                          onChange={(e) => {
                            setText(e.target.value);
                            setSlashIndex(0);
                            setSlashDismissed(false);
                          }}
                          onKeyDown={(e) => {
                            if (
                              slashOpen &&
                              !e.nativeEvent.isComposing &&
                              !e.shiftKey
                            ) {
                              if (e.key === "Escape") {
                                e.preventDefault();
                                e.stopPropagation();
                                setSlashDismissed(true);
                                return;
                              }
                              if (
                                entries.length &&
                                (e.key === "ArrowDown" || e.key === "ArrowUp")
                              ) {
                                e.preventDefault();
                                setSlashIndex(
                                  (index) =>
                                    (index +
                                      (e.key === "ArrowDown" ? 1 : -1) +
                                      entries.length) %
                                    entries.length,
                                );
                                return;
                              }
                              if (
                                selectedSlash &&
                                (e.key === "Enter" || e.key === "Tab")
                              ) {
                                e.preventDefault();
                                insertSlash(selectedSlash);
                                return;
                              }
                            }
                            if (
                              e.key === "Tab" &&
                              e.shiftKey &&
                              !e.nativeEvent.isComposing
                            ) {
                              e.preventDefault();
                              cycleMode();
                            }
                            if (
                              e.key === "Enter" &&
                              !e.shiftKey &&
                              !e.nativeEvent.isComposing
                            ) {
                              e.preventDefault();
                              void submit();
                            }
                          }}
                          placeholder={
                            active
                              ? "Write a follow-up, Enter to queue…"
                              : "Ask anything, / for commands and skills…"
                          }
                          rows={2}
                        />
                        <div className="op-compose-controls">
                          <div className="op-mode-controls">
                            <input
                              ref={fileInput}
                              type="file"
                              multiple
                              hidden
                              aria-label="Choose attachments"
                              onChange={(event) => {
                                addAttachments(
                                  Array.from(event.target.files ?? []),
                                );
                                event.target.value = "";
                              }}
                            />
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              aria-label="Attach files"
                              title="Attach files (up to 20 MB per message)"
                              disabled={busy}
                              onClick={() => fileInput.current?.click()}
                            >
                              <Paperclip size={14} aria-hidden="true" />
                            </Button>
                            <Button
                              size="xs"
                              variant="ghost"
                              className="op-mode"
                              disabled={modeLocked}
                              aria-label={`Mode: ${mode}. Click or press Shift+Tab in the message input to cycle.`}
                              title="Cycle mode (Shift+Tab in message input)"
                              onClick={cycleMode}
                            >
                              {mode === "auto"
                                ? "Automatic"
                                : mode === "plan"
                                  ? "Plan"
                                  : "Manual"}
                            </Button>
                            <span className="op-shortcut">Shift+Tab</span>
                            {state.sessionId && (
                              <ToolPicker
                                sessionId={state.sessionId}
                                disabled={active || state.strike || state.lance}
                                open={isFocused && toolsOpen}
                                onOpenChange={setToolsOpen}
                              />
                            )}
                            <ModelPicker
                              models={modelSettings?.models}
                              selected={modelSettings?.selected}
                              current={state.modelLoading || state.model}
                              active={active}
                              open={isFocused && modelsOpen}
                              onOpenChange={setModelsOpen}
                              onSettings={() => onSettings?.("Providers")}
                              onSelectModel={async (id) => {
                                if (state.sessionId)
                                  apply(
                                    await client.operatorAction({
                                      sessionId: state.sessionId,
                                      action: { type: "model", id },
                                    }),
                                  );
                              }}
                            />
                            {state.sessionId &&
                              (state.lance || state.strike) && (
                                <span>{state.lance ? "Lance" : "Strike"}</span>
                              )}
                            {active && (
                              <span className="op-status">
                                {state.approvals.length
                                  ? "Awaiting approval"
                                  : state.status}
                              </span>
                            )}
                          </div>
                          <div className="actions">
                            <Button
                              variant={active ? "default" : "constructive"}
                              size="icon-sm"
                              aria-label={active ? "Stop turn" : "Send message"}
                              title={
                                active ? "Stop turn" : "Send message (Enter)"
                              }
                              disabled={
                                busy ||
                                state.status === "stopping" ||
                                (!active &&
                                  ((!text.trim() && !attachments.length) ||
                                    !!state.questions ||
                                    state.reviewPlan))
                              }
                              onClick={() =>
                                active
                                  ? void action({ type: "cancel" })
                                  : void submit()
                              }
                            >
                              {active ? (
                                <Square
                                  size={14}
                                  fill="currentColor"
                                  aria-hidden="true"
                                />
                              ) : (
                                <ArrowUp size={16} aria-hidden="true" />
                              )}
                            </Button>
                          </div>
                        </div>
                      </div>
                    )}
                    {!state.sessionId && cwd && (
                      <div className="op-project">
                        <button
                          type="button"
                          disabled={!onChooseFolder}
                          onClick={() => void onChooseFolder?.()}
                          title={cwd}
                        >
                          <svg
                            width="14"
                            height="14"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="1.5"
                            aria-hidden="true"
                          >
                            <path d="M3 7V5h6l2 2h10v12H3Z" />
                          </svg>
                          {cwd.split(/[\\/]/).filter(Boolean).at(-1) || cwd}
                        </button>
                        <span title={cwd}>{cwd}</span>
                      </div>
                    )}
                  </div>
                  {inspecting && (
                    <section className="op-inspector">
                      <div className="actions">
                        <Button
                          size="xs"
                          onClick={() => setVerbose(!verbose)}
                          aria-pressed={verbose}
                        >
                          Verbose
                        </Button>
                      </div>
                      <label className="op-panel-select">
                        Inspect{" "}
                        <select
                          value={panel}
                          onChange={(e) => setPanel(e.target.value as Panel)}
                        >
                          {panels.map((p) => (
                            <option key={p}>{p}</option>
                          ))}
                        </select>
                      </label>
                      {panel === "Overview" && (
                        <>
                          <dl>
                            <dt>Session</dt>
                            <dd>
                              {state.sessionId ||
                                "Created when you send your first message"}
                            </dd>
                            <dt>Target</dt>
                            <dd>{state.target || "Local workspace"}</dd>
                            <dt>Tokens in / out</dt>
                            <dd>
                              {state.usage.input.toLocaleString()} /{" "}
                              {state.usage.output.toLocaleString()}
                            </dd>
                            {state.usage.context !== undefined && (
                              <>
                                <dt>Context</dt>
                                <dd>
                                  {state.usage.context.toLocaleString()} /{" "}
                                  {state.usage.limit?.toLocaleString()}
                                </dd>
                              </>
                            )}
                          </dl>
                          <Button
                            size="sm"
                            disabled={!state.sessionId}
                            onClick={() => action({ type: "open-folder" })}
                          >
                            Open session folder
                          </Button>
                        </>
                      )}
                      {panel === "Plan" && (
                        <pre>
                          {state.plan ||
                            "Switch to Plan mode and describe the objective to draft a plan."}
                        </pre>
                      )}
                      {panel === "Headers" && (
                        <>
                          <p>Request headers for this session.</p>
                          {state.headers.map((h) => (
                            <div key={h.name} className="op-header">
                              <code>
                                {h.name}: {h.displayValue}
                              </code>
                              <Button
                                size="xs"
                                disabled={busy}
                                onClick={() =>
                                  action({
                                    type: "headers",
                                    command: `/headers remove ${h.name}`,
                                  })
                                }
                              >
                                Remove
                              </Button>
                            </div>
                          ))}
                          <form
                            onSubmit={async (e) => {
                              e.preventDefault();
                              if (
                                await action({
                                  type: "headers",
                                  command: `/headers set ${header}`,
                                })
                              )
                                setHeader("");
                            }}
                          >
                            <Input
                              aria-label="Session header"
                              type="password"
                              placeholder="Name: value"
                              value={header}
                              onChange={(e) => setHeader(e.target.value)}
                            />
                            <Button
                              size="sm"
                              disabled={
                                !state.sessionId || busy || !header.trim()
                              }
                              type="submit"
                            >
                              Set header
                            </Button>
                          </form>
                        </>
                      )}
                      {panel === "Skills" &&
                        state.skills.map((s) => (
                          <div className="op-skill" key={s.slug}>
                            <strong>{s.name}</strong>
                            <p>{s.description}</p>
                            <Button
                              size="xs"
                              disabled={!state.sessionId || busy || state.lance}
                              onClick={() =>
                                action({ type: "skill", slug: s.slug })
                              }
                            >
                              Run /{s.slug}
                            </Button>
                          </div>
                        ))}
                      {panel === "Help" && (
                        <>
                          <p>
                            Enter sends a message. Shift+Enter adds a line.
                            Messages sent during a turn enter the queue.
                            Shift+Tab in the message input cycles Manual,
                            Automatic and Plan modes.
                          </p>
                          <dl>
                            {[
                              ["/new", "New conversation"],
                              [
                                "/goal <objective> [--rounds N]",
                                "Start a persistent goal",
                              ],
                              ["/goal", "Show goal status"],
                              ["/goal clear", "End the current goal"],
                              [
                                "/operator --target <host>",
                                "Configure a new session",
                              ],
                              ["/models", "Model and effort"],
                              ["/plan", "Current plan"],
                              ["/tools", "Available tools"],
                              ["/headers", "Session headers"],
                              ["/skills", "Skill catalog"],
                              ["/pentest", "Pentest wizard"],
                              ["/resume", "Session history"],
                              ["/open-session", "Open artifacts"],
                            ].map(([name, label]) => (
                              <div key={name}>
                                <dt>{name}</dt>
                                <dd>{label}</dd>
                              </div>
                            ))}
                          </dl>
                        </>
                      )}
                    </section>
                  )}
                </div>
              </ResizablePanel>
              {sidebarOpen && state.sessionId && (
                <>
                  <ResizableHandle
                    className="op-surface-resize"
                    aria-label={
                      browserOpen
                        ? "Resize browser sidebar"
                        : issuesOpen
                          ? "Resize issues sidebar"
                          : processesOpen
                            ? "Resize processes sidebar"
                            : "Resize attack surface sidebar"
                    }
                  />
                  <ResizablePanel
                    id={surfaceId}
                    defaultSize={`${surfaceWidth.current}%`}
                    minSize="30%"
                    maxSize="75%"
                    className="op-surface-panel"
                  >
                    {browserOpen ? (
                      <Browser
                        onViewport={setBrowserViewport}
                        key={state.sessionId}
                        client={client}
                        active={visible}
                        onClose={() => {
                          setBrowserOpen(false);
                          browserTrigger.current?.focus();
                        }}
                      />
                    ) : issuesOpen ? (
                      <Issues
                        key={state.sessionId}
                        sessionId={state.sessionId}
                        active={visible}
                        onClose={() => {
                          setIssuesOpen(false);
                          issuesTrigger.current?.focus();
                        }}
                      />
                    ) : processesOpen ? (
                      <Processes
                        processes={processes}
                        busy={busy}
                        onCancel={(jobId) =>
                          void action({ type: "cancel-process", jobId })
                        }
                        onClose={() => {
                          setProcessesOpen(false);
                          (processTrigger.current ?? input.current)?.focus();
                        }}
                      />
                    ) : (
                      <AttackSurface
                        key={state.sessionId}
                        client={client}
                        sessionId={state.sessionId}
                        active={visible}
                        onClose={() => {
                          setSurfaceOpen(false);
                          surfaceTrigger.current?.focus();
                        }}
                      />
                    )}
                  </ResizablePanel>
                </>
              )}
            </ResizablePanelGroup>
            {isFocused && setupOpen && (
              <Dialog
                open
                onOpenChange={(open) => {
                  setSetupOpen(open);
                  if (!open) setPrefill(undefined);
                }}
              >
                <DialogContent className="op-config-dialog">
                  <DialogHeader>
                    <DialogTitle>Configure a new session</DialogTitle>
                    <DialogDescription>
                      Review the command options before starting.
                    </DialogDescription>
                  </DialogHeader>
                  <OperatorSetup
                    key={formKey}
                    initial={prefill}
                    busy={busy}
                    cancel={() => {
                      setSetupOpen(false);
                      setPrefill(undefined);
                    }}
                    start={async (options) => {
                      setBusy(true);
                      setError("");
                      try {
                        const launch = {
                          ...options,
                          attachments: await encodeAttachments(
                            attachments.map(({ file }) => file),
                          ),
                        };
                        if (state.sessionId) await onNewSession(launch);
                        else apply(await client.operatorStart(launch));
                        setAttachments([]);
                        setSetupOpen(false);
                        setPrefill(undefined);
                        setText("");
                        setAgentPath([]);
                        setPanel("Overview");
                      } catch (e) {
                        setError(String(e));
                      } finally {
                        setBusy(false);
                      }
                    }}
                  />
                </DialogContent>
              </Dialog>
            )}
          </>
        )}
      </div>
    </BrowserLinkContext.Provider>
  );
}
