import { Button } from "@pensarai/design-system/ui/button";
import { Input } from "@pensarai/design-system/ui/input";
import { Textarea } from "@pensarai/design-system/ui/textarea";
import { useCallback, useEffect, useRef, useState } from "react";
import { splitCommand } from "../commands";
import { runAppearanceCommand } from "../settings/appearance";
import type { SettingsTab } from "../settings/contract";
import { api, operatorEvents } from "../view/bridge";
import type {
  OperatorAction,
  OperatorLaunch,
  OperatorMode,
  OperatorSnapshot,
} from "./contract";
import { applyFrame, type OperatorFrame } from "./live";
import { Questions } from "./Questions";
import { OperatorSetup } from "./Setup";
import { ToolPicker } from "./ToolPicker";
import { Transcript } from "./Transcript";
import "./operator.css";

type Panel = "Overview" | "Subagents" | "Plan" | "Headers" | "Skills" | "Help";
const panels: Panel[] = [
  "Overview",
  "Subagents",
  "Plan",
  "Headers",
  "Skills",
  "Help",
];
interface Props {
  initialSessionId?: string;
  onSettings?: (tab?: SettingsTab) => void;
  onPentest?: (command: string) => Promise<void>;
  onSessions?: (id?: string) => void;
  onSkills?: (slug?: string) => void;
  onRuns?: (command: string) => Promise<void>;
  onExit?: () => void;
}

export default function Operator({
  initialSessionId,
  onSettings,
  onPentest,
  onRuns,
  onExit,
  onSessions,
  onSkills,
}: Props) {
  const [state, setState] = useState<OperatorSnapshot>();
  const [panel, setPanel] = useState<Panel>("Overview");
  const [creating, create] = useState(false);
  const [prefill, setPrefill] = useState<OperatorLaunch>();
  const [formKey, setFormKey] = useState(0);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [text, setText] = useState("");
  const [agentId, selectAgent] = useState("");
  const [header, setHeader] = useState("");
  const [verbose, setVerbose] = useState(false);
  const [toolsOpen, setToolsOpen] = useState(false);
  const input = useRef<HTMLTextAreaElement>(null);
  const latest = useRef<OperatorSnapshot>(undefined);
  const apply = useCallback((next: OperatorSnapshot) => {
    if (!latest.current || next.revision >= latest.current.revision) {
      latest.current = next;
      setState(next);
    }
  }, []);
  useEffect(() => {
    let active = true;
    const key = crypto.randomUUID();
    const refresh = () =>
      api
        .operatorWatch({ key })
        .then((s) => {
          if (active) apply(s);
        })
        .catch((e) => {
          if (active) setError(String(e));
        });
    const receive = (e: Event) => {
      const frame = (e as CustomEvent<OperatorFrame>).detail;
      const current = latest.current;
      if (current && frame.state.revision <= current.revision) return;
      if (!current || current.revision < frame.baseRevision) {
        void refresh();
        return;
      }
      apply(applyFrame(current, frame));
    };
    operatorEvents.addEventListener("snapshot", receive);
    setError("");
    create(false);
    void refresh()
      .then(async () => {
        if (active && initialSessionId)
          apply(await api.operatorResume({ id: initialSessionId }));
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    return () => {
      active = false;
      operatorEvents.removeEventListener("snapshot", receive);
      void api.operatorUnwatch({ key }).catch(console.error);
    };
  }, [initialSessionId, apply]);
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
    return perform(() => api.operatorAction({ sessionId, action: command }));
  }
  const submit = async () => {
    const value = text.trim();
    if (!value || busy) return;
    if (value.startsWith("/")) {
      setError("");
      try {
        const [raw, ...args] = splitCommand(value.slice(1));
        const aliases: Record<string, string> = {
          o: "operator",
          w: "pentest",
          p: "pentest",
          web: "pentest",
          s: "resume",
          sessions: "resume",
          tm: "threat-model",
          pi: "prompt-injection",
          t: "tools",
          auth: "login",
          buy: "credits",
          redact: "obfuscate",
          "advanced-settings": "advanced",
          theme: "themes",
          model: "models",
          q: "exit",
          quit: "exit",
        };
        const cmd = aliases[raw?.toLowerCase()] ?? raw?.toLowerCase();
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
          case "operator":
          case "threat-model":
          case "prompt-injection": {
            if (active)
              throw new Error(
                "Finish or cancel the current turn before starting a new session.",
              );
            setText("");
            setPrefill(
              cmd === "new"
                ? undefined
                : await api.operatorArguments({ command: value }),
            );
            setFormKey((n) => n + 1);
            create(true);
            break;
          }
          case "resume":
            if (!onSessions) throw new Error("Open Sessions from the sidebar.");
            onSessions(args[0]);
            break;
          case "tools":
            setToolsOpen(true);
            break;
          case "models":
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
            setPanel("Help");
            break;
          case "headers":
            setPanel("Headers");
            if (!(await action({ type: "headers", command: value }))) return;
            break;
          case "plan":
            setPanel("Plan");
            break;
          case "skills":
            if (onSkills) onSkills(args[0]);
            else setPanel("Skills");
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
            if (!state?.skills.some((skill) => skill.slug === cmd))
              throw new Error(
                "Unknown operator command. Enter /help for available commands.",
              );
            if (
              !(await action({
                type: "skill",
                slug: cmd,
                autopilot: args.includes("--autopilot"),
                arguments: args.filter((a) => a !== "--autopilot"),
              }))
            )
              return;
        }
      } catch (e) {
        setError(String(e));
        return;
      }
    } else if (!state?.sessionId || creating) {
      setError(
        "Use / for workspace commands. Enter an objective in First message to start a session.",
      );
      return;
    } else if (!(await action({ type: "send", text: value }))) return;
    setText("");
    input.current?.focus();
  };
  const active = !!state && state.status !== "idle";
  const current =
    state?.subagents.find((a) => a.id === agentId) ?? state?.subagents.at(-1);
  return (
    <div className="op-page">
      <header>
        <div>
          <h1>Operator</h1>
          <p>
            {state?.sessionId && !creating
              ? state.name
              : "Interactive security testing"}
          </p>
        </div>
        <div className="actions">
          {state?.sessionId && !creating && (
            <Button
              disabled={active || busy}
              onClick={() => {
                setPrefill(undefined);
                setFormKey((n) => n + 1);
                create(true);
              }}
            >
              New session
            </Button>
          )}
          {onSettings && <Button onClick={() => onSettings()}>Settings</Button>}
        </div>
      </header>
      {error && <p role="alert">{error}</p>}
      {!state ? (
        <p className="empty">
          {error ? "Unable to open operator." : "Opening operator…"}
        </p>
      ) : !state.sessionId || creating ? (
        <>
          <form
            className="op-launch-command"
            onSubmit={(e) => {
              e.preventDefault();
              void submit();
            }}
          >
            <Input
              aria-label="Workspace command"
              value={text}
              placeholder="Workspace command, e.g. /skills"
              onChange={(e) => setText(e.target.value)}
            />
            <Button type="submit" size="sm" disabled={busy || !text.trim()}>
              Run command
            </Button>
          </form>
          {panel === "Help" && (
            <p className="op-launch-command">
              Use /operator to configure a session, /pentest to prepare a test,
              /resume to open session history, or /models and /providers to
              configure inference.
            </p>
          )}
          <OperatorSetup
            key={formKey}
            initial={prefill}
            busy={busy}
            cancel={state.sessionId ? () => create(false) : undefined}
            start={async (options) => {
              if (await perform(() => api.operatorStart(options))) {
                create(false);
                setText("");
                selectAgent("");
                setPanel("Overview");
              }
            }}
          />
        </>
      ) : (
        <>
          <div className="op-toolbar">
            <label>
              Mode{" "}
              <select
                value={state.mode}
                disabled={
                  busy || !!state.questions || state.reviewPlan || state.lance
                }
                onChange={(e) =>
                  void action({
                    type: "mode",
                    mode: e.target.value as OperatorMode,
                  })
                }
              >
                <option value="manual">Manual</option>
                <option value="auto">Automatic</option>
                <option value="plan">Plan</option>
              </select>
            </label>
            <span>
              {state.lance ? "Lance" : state.strike ? "Strike" : "Standard"}
            </span>
            <span className="op-status">
              {state.approvals.length ? "Awaiting approval" : state.status}
            </span>
            <button type="button" onClick={() => onSettings?.("Models")}>
              {state.modelLoading || state.model || "Model settings"}
            </button>
            <Button
              size="xs"
              onClick={() => setVerbose(!verbose)}
              aria-pressed={verbose}
            >
              Verbose
            </Button>
            <ToolPicker
              sessionId={state.sessionId}
              disabled={active || state.strike || state.lance}
              open={toolsOpen}
              onOpenChange={setToolsOpen}
            />
          </div>
          <div className="op-body">
            <div className="op-chat">
              <Transcript
                key={state.sessionId}
                messages={state.messages}
                sessionId={state.sessionId}
                verbose={verbose}
              />
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
                              action({ type: "approval", id: a.id, decision })
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
                        onClick={() => action({ type: "plan", approve: true })}
                      >
                        Approve plan
                      </Button>
                      <Button
                        disabled={busy || state.status !== "waiting"}
                        onClick={() => action({ type: "plan", approve: false })}
                      >
                        Request changes
                      </Button>
                    </div>
                  </div>
                )}
              </div>
              <div className="op-compose">
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
                        action({ type: "queue", id: q.id, operation: "remove" })
                      }
                    >
                      Remove
                    </Button>
                  </div>
                ))}
                <Textarea
                  ref={input}
                  aria-label="Operator message"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  onKeyDown={(e) => {
                    if (
                      e.key === "Enter" &&
                      !e.shiftKey &&
                      !e.nativeEvent.isComposing
                    ) {
                      e.preventDefault();
                      void submit();
                    }
                  }}
                  placeholder="Message the operator, or enter /help"
                  rows={2}
                />
                <div className="actions">
                  <Button
                    variant="constructive"
                    disabled={
                      !text.trim() ||
                      busy ||
                      !!state.questions ||
                      state.reviewPlan ||
                      state.status === "stopping"
                    }
                    onClick={() => void submit()}
                  >
                    {active ? "Queue message" : "Send"}
                  </Button>
                  {active && (
                    <>
                      <Button
                        disabled={busy || state.status === "stopping"}
                        onClick={() => action({ type: "cancel" })}
                      >
                        Stop turn
                      </Button>
                      {state.status === "running" && (
                        <Button
                          disabled={busy}
                          onClick={() => action({ type: "cancel-command" })}
                        >
                          Cancel command
                        </Button>
                      )}
                    </>
                  )}
                </div>
              </div>
            </div>
            <section className="op-inspector">
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
                    <dd>{state.sessionId}</dd>
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
                    onClick={() => action({ type: "open-folder" })}
                  >
                    Open session folder
                  </Button>
                  <h3>Subagents ({state.subagents.length})</h3>
                  {state.subagents.map((a) => (
                    <button
                      className="op-agent"
                      type="button"
                      key={a.id}
                      onClick={() => {
                        selectAgent(a.id);
                        setPanel("Subagents");
                      }}
                    >
                      {a.name}
                      <small>{a.status}</small>
                    </button>
                  ))}
                </>
              )}
              {panel === "Subagents" &&
                (current ? (
                  <>
                    <label>
                      Subagent
                      <select
                        value={current.id}
                        onChange={(e) => selectAgent(e.target.value)}
                      >
                        {state.subagents.map((a) => (
                          <option key={a.id} value={a.id}>
                            {a.name} · {a.status}
                          </option>
                        ))}
                      </select>
                    </label>
                    {current.input != null && (
                      <details>
                        <summary>Objective</summary>
                        <pre>{JSON.stringify(current.input, null, 2)}</pre>
                      </details>
                    )}
                    <Transcript
                      key={current.id}
                      messages={current.messages}
                      sessionId={state.sessionId}
                      agentId={current.id}
                      verbose={verbose}
                    />
                  </>
                ) : (
                  <p>No subagents have started.</p>
                ))}
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
                      disabled={busy || !header.trim()}
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
                      disabled={busy || state.lance}
                      onClick={() => action({ type: "skill", slug: s.slug })}
                    >
                      Run /{s.slug}
                    </Button>
                  </div>
                ))}
              {panel === "Help" && (
                <>
                  <p>
                    Enter sends a message. Shift+Enter adds a line. Messages
                    sent during a turn enter the queue.
                  </p>
                  <dl>
                    {[
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
          </div>
        </>
      )}
    </div>
  );
}
