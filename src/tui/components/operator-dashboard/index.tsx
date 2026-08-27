/**
 * Operator Dashboard
 *
 * Interactive operator mode that uses the OffensiveSecurityAgent
 * with streaming message display and chat input.
 * Reuses MessageList and InputArea from the shared/chat components.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { useKeyboard } from "@opentui/react";
import { hasToolCall, type ModelMessage, stepCountIs } from "ai";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import type {
  AskUserQuestion,
  AskUserQuestionAnswer,
  AskUserQuestionsResult,
} from "../../../core/agents/offSecAgent";
import {
  AgentEventBus,
  type AgentMode,
  ALL_TOOL_NAMES,
  ASK_USER_QUESTIONS_TOOL_NAME,
  PLAN_MODE_TOOL_NAMES,
  SKILL_TOOL_NAMES,
} from "../../../core/agents/offSecAgent";
import {
  buildAuthConfig,
  type CacheMetrics,
  getContextWindow,
  modelSupportsOpenAIReasoning,
  modelSupportsThinking,
} from "../../../core/ai";
import {
  type RunAgentResult,
  runOffensiveSecurityAgent,
} from "../../../core/api";
import { formatParseError, parseHeaderLine } from "../../../core/http/parse";
import {
  isSensitiveHeaderName,
  renderHeaderValue,
} from "../../../core/http/types";
import type { OperatorMode, PendingApproval } from "../../../core/operator";
import {
  ApprovalGate,
  createInitialOperatorState,
  OPERATOR_MODE_CYCLE,
  type OperatorSessionState,
} from "../../../core/operator";
import {
  planFilePath as getPlanFilePath,
  hasPlan,
  readPlan,
} from "../../../core/plan";
import {
  normalizeMessages,
  type SessionConfig,
  type SessionInfo,
  sessions,
} from "../../../core/session";
import {
  readExecutionMetrics,
  writeExecutionMetrics,
} from "../../../core/session/execution-metrics";
import {
  convertModelMessagesToUI,
  type UIMessage,
} from "../../../core/session/persistence";
import {
  buildPentestPrompt,
  buildThreatModelPrompt,
} from "../../../core/skills/builtins";
import { useAgent } from "../../context/agent";
import { useCommand } from "../../context/command";
import { useConfig } from "../../context/config";
import { useDialog } from "../../context/dialog";
import { useFocus } from "../../context/focus";
import { useRoute } from "../../context/route";
import { useTheme } from "../../theme";
import { openFileInDefaultApp } from "../../utils/open-file.js";
import type { DisplayMessage, WorkflowData } from "../agent-display";
import { InputArea } from "../chat/input-area";
import { MessageList } from "../chat/message-list";
import { QuestionsForm } from "../chat/questions-form";
import { collectScreenshotPaths, ScreenshotModal } from "../screenshot-modal";
import { deriveApprovedActionLabel, isToolMessage } from "../shared";
import {
  recoverAbortedTranscript,
  rewriteToolResultOutput,
} from "./conversation";
import { markInFlightToolsErrored } from "./display-state";
import {
  buildOperatorSystemPrompt,
  type DashboardStatus,
  filterOperatorAutocomplete,
  resolveAbortAction,
  resolveInputFocused,
  resolveKeyboardShortcut,
  resolveOperatorAgentMode,
  resolveOperatorStrikeMode,
  resolveSubmit,
  routeCommand,
} from "./logic";
import {
  createQueuedMessage,
  navigateDown,
  navigateUp,
  type QueuedMessage,
  selectionAfterRemove,
} from "./queue";
import { QueuedMessages } from "./queued-messages";
import {
  bindOperatorRunEvents,
  createDisplayEventHandlers,
  createRunEventProjections,
} from "./run-events";
import { RunTraceSession } from "./run-tracing";
import SubagentDialog from "./subagent-dialog";
import {
  createSubagentSessionHelpers,
  createSubagentStore,
  loadSubagentSessionsFromDisk,
  markSubagentsInterrupted,
} from "./subagent-state";
import { SubagentStatusBar } from "./subagent-status-bar";
import { updateWorkflowDataMessage } from "./workflow-data";

/**
 * Operator Dashboard - interactive chat interface with the offensive security agent
 */
export default function OperatorDashboard({
  sessionId,
  initialMessage,
  initialConfig,
}: {
  sessionId?: string;
  initialMessage?: string;
  initialConfig?: {
    requireApproval?: boolean;
    target?: string;
    operatorMode?: OperatorMode;
    strikeMode?: boolean;
    sandbox?: boolean;
    taskDriven?: boolean;
    headers?: Record<string, string>;
    promptInjectionLibrarySource?: string;
  };
}) {
  const { colors } = useTheme();
  const route = useRoute();
  const config = useConfig();
  const {
    model,
    setModel,
    isModelUserSelected,
    setThinking,
    setIsExecuting,
    tokenUsage,
    usageStore,
    markExecuted,
    setSessionCwd,
    reasoningEnabled,
    openAIReasoningEffort,
  } = useAgent();
  const {
    autocompleteOptions: allAutocompleteOptions,
    commandOptionMap,
    commandNames,
    executeCommand,
    resolveSkillContent,
    skillsRegistry,
    skillsVersion,
  } = useCommand();
  const {
    stack,
    externalDialogOpen,
    replace: replaceDialog,
    clear: clearDialog,
  } = useDialog();
  const { refocusPrompt } = useFocus();
  const initialStrikeModeRef = useRef(
    resolveOperatorStrikeMode({
      resuming: !!sessionId,
      routeOverride: initialConfig?.strikeMode,
      persistedDefault: config.data.strikeMode,
    }),
  );
  const [strikeMode, setStrikeMode] = useState(initialStrikeModeRef.current);

  // biome-ignore lint/correctness/useExhaustiveDependencies: `skillsVersion` is an intentional cache-buster — forces recomputation when skills are refreshed even though `skillsRegistry` (stable ref) hasn't changed.
  const autocompleteOptions = useMemo(() => {
    const commandOptions = filterOperatorAutocomplete(
      allAutocompleteOptions,
    ).filter((option) => !strikeMode || option.value !== "/pentest");
    const skillOptions = skillsRegistry
      .list()
      .filter(
        (skill) =>
          !strikeMode ||
          (skill.slug !== "pentest" && skill.slug !== "threat-model"),
      )
      .map((skill) => {
        const slug = `/${skill.slug}`;
        return {
          value: slug,
          label: slug,
          description: skill.manifest.description || "Skill",
        };
      });
    const operatorOnlyOptions = [
      {
        value: "/open-session",
        label: "/open-session",
        description: "Open session folder in Finder",
      },
    ];
    return [...commandOptions, ...operatorOnlyOptions, ...skillOptions];
  }, [allAutocompleteOptions, skillsRegistry, skillsVersion, strikeMode]);

  // Session state
  const [session, setSession] = useState<SessionInfo | null>(null);
  // Ref mirror so handleAbort always sees the latest session even before
  // React re-renders (critical for first-message abort where setSession
  // hasn't been applied yet).
  const sessionRef = useRef<SessionInfo | null>(null);
  sessionRef.current = session;
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Captures an AI-generated name that arrives before the session is stored in state
  const pendingNameRef = useRef<string | null>(null);

  // Agent/status state
  const [status, setStatus] = useState<DashboardStatus>("idle");
  const abortControllerRef = useRef<AbortController | null>(null);
  const generationRef = useRef(0);

  // Two-stage abort: first Ctrl+C cancels the running command, second kills the agent.
  // The agent populates cancelHandle.cancel with the shell's cancel function.
  const cancelHandleRef = useRef<{ cancel: () => boolean }>({
    cancel: () => false,
  });
  const commandCancelledRef = useRef(false);

  const subagentStore = useMemo(() => createSubagentStore(), []);
  const subagentSessions = useSyncExternalStore(
    subagentStore.subscribe,
    subagentStore.getSnapshot,
  );
  const subagentHelpers = useMemo(
    () => createSubagentSessionHelpers(subagentStore.setState),
    [subagentStore],
  );

  // Track the message count when subagents last finished so the status bar
  // knows whether the main agent has produced new output since then.
  const messageCountAtSubagentDoneRef = useRef<number | null>(null);
  const hasRunningSubagent = useMemo(
    () =>
      Array.from(subagentSessions.values()).some((s) => s.status === "running"),
    [subagentSessions],
  );
  useEffect(() => {
    if (subagentSessions.size > 0 && !hasRunningSubagent) {
      if (messageCountAtSubagentDoneRef.current === null) {
        messageCountAtSubagentDoneRef.current =
          displayMessagesRef.current.length;
      }
    } else if (hasRunningSubagent) {
      messageCountAtSubagentDoneRef.current = null;
    }
  }, [subagentSessions, hasRunningSubagent]);

  const openSubagentDialog = useCallback(() => {
    replaceDialog(<SubagentDialog store={subagentStore} />, {
      selfHandlesEscape: true,
      size: "large",
    });
  }, [replaceDialog, subagentStore]);

  // Messages — same pattern as pentest component
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  // Mirror of `messages` as a ref so handleAbort can read the current display
  // messages synchronously (React state isn't accessible inside event handlers
  // without a ref).
  const displayMessagesRef = useRef<DisplayMessage[]>([]);
  displayMessagesRef.current = messages;
  // AI SDK conversation history for multi-turn continuity
  const conversationRef = useRef<ModelMessage[]>([]);
  // Input state
  const [inputValue, setInputValue] = useState("");

  // Queued follow-up messages
  const [queuedMessages, setQueuedMessages] = useState<QueuedMessage[]>([]);
  const [selectedQueueIndex, setSelectedQueueIndex] = useState(-1);
  const queuedMessagesRef = useRef<QueuedMessage[]>([]);

  // Keep queue ref in sync and clamp selection
  useEffect(() => {
    queuedMessagesRef.current = queuedMessages;
    if (queuedMessages.length === 0) {
      setSelectedQueueIndex(-1);
    } else if (selectedQueueIndex >= queuedMessages.length) {
      setSelectedQueueIndex(queuedMessages.length - 1);
    }
  }, [queuedMessages, selectedQueueIndex]);

  // Operator state
  const [operatorState, setOperatorState] = useState<OperatorSessionState>(() =>
    createInitialOperatorState("manual", true),
  );

  // Approval gate — created once and updated when config changes
  const approvalGateRef = useRef<ApprovalGate>(
    new ApprovalGate({
      requireApproval: (initialConfig?.operatorMode ?? "manual") === "manual",
    }),
  );
  const [pendingApprovals, setPendingApprovals] = useState<PendingApproval[]>(
    [],
  );
  const [lastApprovedAction, setLastApprovedAction] = useState<string | null>(
    null,
  );

  // Display options
  const [verboseMode, setVerboseMode] = useState(false);
  const [expandedLogs, setExpandedLogs] = useState(false);
  // Unified operator mode: combines tool availability + approval gating
  const [operatorMode, setOperatorMode] = useState<OperatorMode>(
    initialConfig?.operatorMode ?? "manual",
  );
  const agentMode: AgentMode = resolveOperatorAgentMode(
    operatorMode,
    strikeMode,
  );
  const requireApproval = operatorMode === "manual";
  // Plan mode review state
  const [approvedPlanContent, setApprovedPlanContent] = useState<string | null>(
    null,
  );
  const [showPlanReview, setShowPlanReview] = useState(false);
  const planSubmittedRef = useRef(false);
  const planRejectedRef = useRef(false);
  const planApprovedPendingRunRef = useRef(false);
  const planGateBypassedOnResumeRef = useRef(false);

  const [pendingQuestions, setPendingQuestions] = useState<
    AskUserQuestion[] | null
  >(null);
  const pendingToolCallIdRef = useRef<string | null>(null);
  const operatorModeRef = useRef(operatorMode);
  useEffect(() => {
    operatorModeRef.current = operatorMode;
  }, [operatorMode]);
  const approvedPlanRef = useRef(approvedPlanContent);
  useEffect(() => {
    approvedPlanRef.current = approvedPlanContent;
  }, [approvedPlanContent]);

  // Subscribe to approval gate events
  useEffect(() => {
    const gate = approvalGateRef.current;

    const onApprovalNeeded = () => {
      setPendingApprovals(gate.getPendingApprovals());
      setStatus("waiting");
    };

    const onApprovalResolved = (event: {
      id: string;
      decision: string;
      approval: PendingApproval;
    }) => {
      const pending = gate.getPendingApprovals();
      setPendingApprovals(pending);
      if (event.decision === "approved") {
        setLastApprovedAction(deriveApprovedActionLabel(event.approval));
      }
      if (pending.length === 0) {
        setStatus("running");
      }
    };

    gate.on("approval-needed", onApprovalNeeded);
    gate.on("approval-resolved", onApprovalResolved);

    return () => {
      gate.off("approval-needed", onApprovalNeeded);
      gate.off("approval-resolved", onApprovalResolved);
    };
  }, []);

  // Load existing session or initialise operator state for a new one.
  // New sessions are created lazily by the agent on the first runAgent call.
  useEffect(() => {
    async function loadSession() {
      try {
        if (sessionId) {
          const s = await sessions.get(sessionId);
          setSession(s);
          setSessionCwd(s.rootPath);
          setStrikeMode(
            resolveOperatorStrikeMode({
              resuming: true,
              savedSessionValue: s.config?.operatorSettings?.strikeMode,
            }),
          );

          const hasState = sessions.hasOperatorState(s);
          if (hasState) {
            const savedState = await sessions.loadOperatorState(sessionId);
            if (savedState) {
              const restoredMode =
                (savedState.mode as OperatorMode) || "manual";
              setOperatorMode(restoredMode);
              setOperatorState((prev) => ({
                ...prev,
                mode: restoredMode,
                requireApproval: restoredMode === "manual",
                currentStage:
                  (savedState.currentStage as OperatorSessionState["currentStage"]) ||
                  prev.currentStage,
              }));
              approvalGateRef.current.updateConfig({
                requireApproval: restoredMode === "manual",
              });

              if (
                Array.isArray(savedState.messages) &&
                savedState.messages.length > 0
              ) {
                const modelMsgs = savedState.messages;

                // Only pass a recent subset to the AI to avoid immediately
                // blowing the context window and triggering summarization.
                conversationRef.current = normalizeMessages(
                  sessions.getResumeMessages(modelMsgs),
                );

                const uiMsgs = convertModelMessagesToUI(modelMsgs);
                setMessages(
                  uiMsgs.map((m: UIMessage) => ({
                    role: m.role,
                    content: m.content,
                    createdAt: m.createdAt,
                    toolCallId: m.toolCallId,
                    toolName: m.toolName,
                    args: m.args,
                    result: m.result,
                    status: m.status,
                  })),
                );
              }

              // Restore subagent sessions from disk so Ctrl+A shows history
              try {
                const restored = loadSubagentSessionsFromDisk(s.rootPath);
                if (restored.size > 0) {
                  subagentStore.setState(restored);
                }
              } catch {
                // Best-effort — subagent files may not exist
              }

              const planContent = readPlan(s.rootPath);
              if (planContent) {
                if (restoredMode !== "plan") {
                  setApprovedPlanContent(planContent);
                } else {
                  planGateBypassedOnResumeRef.current = true;
                }
              }
            }
          } else if (s.config?.operatorSettings) {
            const settings = s.config.operatorSettings;
            const settingsMode =
              (settings.initialMode as OperatorMode) || "manual";
            setOperatorMode(settingsMode);
            const requireApproval = settingsMode === "manual";
            const initialState = createInitialOperatorState(
              settingsMode,
              requireApproval,
            );
            setOperatorState(initialState);
            approvalGateRef.current.updateConfig({ requireApproval });
          }
        } else {
          // New session — just set up operator config; the agent creates the
          // session on the first runAgent call.
          setStrikeMode(initialStrikeModeRef.current);
          const newMode = initialConfig?.operatorMode ?? "manual";
          setOperatorMode(newMode);
          const requireApproval = newMode === "manual";
          const state = createInitialOperatorState(newMode, requireApproval);
          setOperatorState(state);
          approvalGateRef.current.updateConfig({ requireApproval });
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load session");
      } finally {
        setLoading(false);
      }
    }
    loadSession();
  }, [
    sessionId,
    subagentStore.setState,
    initialConfig?.operatorMode,
    setSessionCwd,
  ]);

  useEffect(() => {
    return () => setSessionCwd(null);
  }, [setSessionCwd]);

  // Auto-focus the input when the operator dashboard finishes loading
  useEffect(() => {
    if (!loading) {
      refocusPrompt();
    }
  }, [loading, refocusPrompt]);

  useEffect(() => {
    if (sessionId === undefined) usageStore.beginNewSession();
  }, [sessionId, usageStore]);

  useEffect(() => {
    // Enter the resumed session in the usage store: seeds its totals from
    // persisted metrics when first tracked, and never resets live totals on
    // re-entry (another run in the same session accumulates). Brand-new
    // sessions enter via onSessionReady once the session is minted, carrying
    // the provisional bucket with them.
    if (!session || !sessionId) return;

    const metrics = readExecutionMetrics(session.rootPath);
    usageStore.enterSession(session.id, {
      ...(metrics?.tokenUsage ? { tokenUsage: metrics.tokenUsage } : {}),
      ...(metrics?.contextUsage ? { contextUsage: metrics.contextUsage } : {}),
    });
  }, [session, sessionId, usageStore]);

  // ---------------------------------------------------------------------------
  // Display event adapter — root display projections (partial text, tool-arg
  // deltas, throttled command output) behind the run-event binding. React
  // setters stay behind the narrow sink.
  // ---------------------------------------------------------------------------

  // The session id the CURRENT run belongs to. Usage events route here (not
  // to whichever session is active) so late stragglers from a finishing run
  // never leak into a different session's totals.
  const runSessionIdRef = useRef<string | null>(null);

  const displayEvents = useMemo(
    () =>
      createDisplayEventHandlers({
        updateMessages: setMessages,
        setThinking,
        setError,
      }),
    [setThinking],
  );

  // Clean up the command-output flush timer when the component unmounts
  useEffect(() => {
    return () => {
      displayEvents.dispose();
    };
  }, [displayEvents]);

  // ---------------------------------------------------------------------------
  // Run event projections — subagent routing, questions interception, and
  // workflow phases layered over the display projections. Component state
  // changes stay behind the injected callbacks.
  // ---------------------------------------------------------------------------

  const updateWorkflowData = useCallback(
    (updater: (wd: WorkflowData) => WorkflowData) => {
      setMessages((prev) => updateWorkflowDataMessage(prev, updater));
    },
    [],
  );

  const runEventProjections = useMemo(
    () =>
      createRunEventProjections({
        display: displayEvents,
        subagents: subagentHelpers,
        updateWorkflowData,
        clearSubagentSessions: () => subagentStore.setState(new Map()),
        questions: {
          onAsked: (toolCallId, questions) => {
            pendingToolCallIdRef.current = toolCallId;
            setPendingQuestions(questions);
          },
          onCleared: () => {
            pendingToolCallIdRef.current = null;
            setPendingQuestions(null);
          },
        },
        onRootToolCallStarted: () => {
          commandCancelledRef.current = false;
        },
        onPlanSubmitted: () => {
          planSubmittedRef.current = true;
          planGateBypassedOnResumeRef.current = false;
        },
      }),
    [displayEvents, subagentHelpers, updateWorkflowData, subagentStore],
  );

  // ---------------------------------------------------------------------------
  // Approval handlers
  // ---------------------------------------------------------------------------

  const handleApprove = useCallback(() => {
    const pending = approvalGateRef.current.getPendingApprovals();
    if (pending.length > 0) {
      approvalGateRef.current.approve(pending[0].id);
    }
  }, []);

  const handleAutoApprove = useCallback(() => {
    // Switch to approvals-off mode
    setOperatorMode("auto");
    setOperatorState((prev) => ({
      ...prev,
      mode: "auto",
      requireApproval: false,
    }));
    approvalGateRef.current.updateConfig({ requireApproval: false });

    // Approve all currently pending
    const pending = approvalGateRef.current.getPendingApprovals();
    for (const p of pending) {
      approvalGateRef.current.approve(p.id);
    }
  }, []);

  // ---------------------------------------------------------------------------
  // Run agent
  // ---------------------------------------------------------------------------

  const runAgent = useCallback(
    async (prompt: string | null) => {
      // Abort any previous run before starting a new one
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
        abortControllerRef.current = null;
      }

      const gen = ++generationRef.current;
      runSessionIdRef.current = sessionRef.current?.id ?? session?.id ?? null;

      setStatus("running");
      setThinking(true);
      setIsExecuting(true);
      setError(null);
      displayEvents.resetPartialText();

      const controller = new AbortController();
      abortControllerRef.current = controller;

      const prevMessages = conversationRef.current;

      let nextMessages: ModelMessage[];
      if (prompt !== null) {
        setMessages((prev) => [
          ...prev,
          { role: "user", content: prompt, createdAt: new Date() },
        ]);

        nextMessages = normalizeMessages([
          ...conversationRef.current,
          { role: "user", content: prompt },
        ]);
        conversationRef.current = nextMessages;

        if (sessionRef.current) {
          try {
            const mp = join(sessionRef.current.rootPath, "messages.json");
            writeFileSync(mp, JSON.stringify(nextMessages, null, 2));
          } catch {
            // Best-effort; onStepFinish persists later.
          }
        }
      } else {
        nextMessages = conversationRef.current;
      }

      // THE accounting path: every step (root via onStepFinish, subagents via
      // trace records) funnels through here exactly once. Routes into the
      // run's owning session; metrics write that session's snapshot.
      const recordTokenUsage = (
        inputTokens: number,
        outputTokens: number,
        cacheReadTokens = 0,
        cacheWriteTokens = 0,
      ) => {
        if (inputTokens > 0 || outputTokens > 0) markExecuted();
        const runSessionId = runSessionIdRef.current;
        usageStore.addSessionTokens(runSessionId, {
          inputTokens,
          outputTokens,
          cacheReadTokens,
          cacheWriteTokens,
        });
        const activeSession = sessionRef.current;
        if (activeSession) {
          try {
            writeExecutionMetrics({
              sessionRootPath: activeSession.rootPath,
              tokenUsage: usageStore.getSnapshot(activeSession.id).tokenUsage,
            });
          } catch {
            // Best effort: token metrics should not interrupt operator runs.
          }
        }
      };

      // Root steps also replace the context sample: the step's input is the
      // whole conversation as the model saw it, and the denominator comes
      // from the model this run actually used.
      const runModelId = model.id;
      const recordRootStepUsage = (usage: {
        inputTokens?: number;
        outputTokens?: number;
      }) => {
        recordTokenUsage(usage.inputTokens ?? 0, usage.outputTokens ?? 0);
        const inputTokens = usage.inputTokens ?? 0;
        if (inputTokens > 0) {
          usageStore.setRootContext(runSessionIdRef.current, {
            usedTokens: inputTokens,
            contextLimit: getContextWindow(runModelId),
            modelId: runModelId,
          });
        }
      };

      const onStepFinish = (event: {
        usage?: { inputTokens?: number; outputTokens?: number };
      }) => {
        recordRootStepUsage(event.usage ?? {});
      };

      const eventBus = new AgentEventBus();

      // W&B trace upload — buffer early records so none are lost for new sessions.
      // For resumed sessions, we attach before the agent starts.
      // For new sessions, onSessionReady fires mid-construction; we replay
      // any buffered records once the handler attaches.
      const runTrace = new RunTraceSession(eventBus, {
        isCurrent: () => gen === generationRef.current,
        recordTokenUsage,
      });

      const unbindRunEvents = bindOperatorRunEvents(eventBus, {
        isCurrent: () => gen === generationRef.current,
        handlers: runEventProjections.handlers,
      });

      const skillsCatalog = skillsRegistry.buildCatalog() || undefined;

      const commonInput = {
        prompt: prompt ?? "",
        model: model.id,
        messages: nextMessages,
        stopWhen: [
          stepCountIs(10000),
          hasToolCall(ASK_USER_QUESTIONS_TOOL_NAME),
        ],
        target: initialConfig?.target,
        activeTools: [
          ...(agentMode === "plan" ? PLAN_MODE_TOOL_NAMES : ALL_TOOL_NAMES),
          ...SKILL_TOOL_NAMES,
        ] as string[],
        mode: agentMode,
        abortSignal: controller.signal,
        authConfig: buildAuthConfig(config.data),
        approvalGate: approvalGateRef.current,
        commandCancelHandle: cancelHandleRef.current,
        skillsRegistry,
        enableThinking: reasoningEnabled && modelSupportsThinking(model.id),
        openAIReasoningEffort: modelSupportsOpenAIReasoning(model.id)
          ? openAIReasoningEffort
          : undefined,
        surfaceIntegrationEnabled: config.data?.surfaceIntegrationEnabled,
        promptInjectionLibrarySource:
          initialConfig?.promptInjectionLibrarySource ??
          (route.data.type === "operator"
            ? route.data.initialSkill?.args?.library
            : undefined),
        onStepFinish,
        onCacheMetrics: (metrics: CacheMetrics) => {
          usageStore.addSessionTokens(runSessionIdRef.current, {
            cacheReadTokens: metrics.cacheReadInputTokens,
            cacheWriteTokens: metrics.cacheCreationInputTokens,
          });
        },
        eventBus,
        onSessionReady: (s: SessionInfo) => {
          setSessionCwd(s.rootPath);
          sessionRef.current = s;
          setSession((prev) => prev ?? s);
          runSessionIdRef.current = s.id;
          usageStore.enterSession(s.id);
          runTrace.tryAttach(s);
        },
      };

      const wandbSession = session ?? sessionRef.current;
      if (wandbSession) {
        await runTrace.tryAttach(wandbSession);
      }

      try {
        let agentResult: RunAgentResult;

        const systemPrompt = buildOperatorSystemPrompt(
          initialConfig?.target,
          operatorState,
          agentMode,
          {
            requireApproval,
            sandboxMode: !!initialConfig?.sandbox,
            skillsCatalog,
            planFilePath: sessionRef.current
              ? getPlanFilePath(sessionRef.current.rootPath)
              : undefined,
            existingPlanContent:
              agentMode === "plan" &&
              planRejectedRef.current &&
              sessionRef.current
                ? readPlan(sessionRef.current.rootPath)
                : null,
            approvedPlanContent:
              agentMode !== "plan" ? approvedPlanRef.current : null,
            taskDriven:
              session?.config?.taskDriven ?? initialConfig?.taskDriven,
          },
        );

        if (session) {
          agentResult = await runOffensiveSecurityAgent({
            ...commonInput,
            system: systemPrompt,
            session,
          });
        } else {
          // First call — let the agent factory create the session
          const sessionConfig: SessionConfig = {
            sessionType: "web-app",
            mode: "operator",
            operatorSettings: {
              initialMode: operatorMode,
              requireApproval,
              enableSuggestions: true,
              strikeMode,
            },
            agentCwd: initialConfig?.sandbox ? undefined : process.cwd(),
            codebasePath: initialConfig?.sandbox ? undefined : process.cwd(),
            taskDriven: initialConfig?.taskDriven,
            ...(initialConfig?.headers !== undefined
              ? { headers: { ...initialConfig.headers } }
              : {}),
            promptInjectionLibrarySource:
              initialConfig?.promptInjectionLibrarySource ??
              (route.data.type === "operator"
                ? route.data.initialSkill?.args?.library
                : undefined),
          };
          agentResult = await runOffensiveSecurityAgent({
            ...commonInput,
            system: systemPrompt,
            sessionConfig,
            onNameGenerated: (name: string) => {
              pendingNameRef.current = name;
              setSession((prev) => (prev ? { ...prev, name } : prev));
            },
          });
          // Apply any AI-generated name that arrived while the stream was running
          const created = agentResult.session;
          if (pendingNameRef.current) {
            created.name = pendingNameRef.current;
            pendingNameRef.current = null;
          }
          setSession(created);
          setSessionCwd(created.rootPath);
        }

        // Sync conversationRef from the agent's persisted state.
        // messages.json is the single source of truth — after summarization
        // the agent discards stale history, so reading back avoids
        // re-accumulating old messages that would overflow the context.
        if (gen === generationRef.current) {
          try {
            const rootPath = agentResult.session.rootPath;
            const mp = join(rootPath, "messages.json");
            if (existsSync(mp)) {
              const raw = JSON.parse(readFileSync(mp, "utf-8"));
              if (Array.isArray(raw) && raw.length > 0) {
                conversationRef.current = normalizeMessages(
                  sessions.getResumeMessages(raw as ModelMessage[]),
                );
              }
            }
          } catch {
            // Best effort — fall back to stream response
            try {
              const response = await agentResult.streamResult.response;
              if (response.messages) {
                conversationRef.current = normalizeMessages([
                  ...nextMessages,
                  ...response.messages,
                ] as ModelMessage[]);
              }
            } catch {
              // conversation stays as-is
            }
          }
        }
      } catch (e) {
        if (gen !== generationRef.current) return;
        if ((e as Error).name !== "AbortError") {
          // Roll back the eagerly-appended user message so the conversation
          // state stays clean.  Without this, a schema validation failure
          // (e.g. from the AI SDK) leaves the user message in place and
          // subsequent retries stack consecutive user messages, permanently
          // breaking the session.
          conversationRef.current = prevMessages;
          // Clear pending-questions state so the finally block doesn't set
          // status to "waiting" over a rolled-back conversation.
          pendingToolCallIdRef.current = null;
          setPendingQuestions(null);
          if (sessionRef.current) {
            try {
              const mp = join(sessionRef.current.rootPath, "messages.json");
              writeFileSync(mp, JSON.stringify(prevMessages, null, 2));
            } catch {
              // Best-effort rollback
            }
          }

          const errorMsg = e instanceof Error ? e.message : "Agent failed";
          setError(errorMsg);
          setMessages((prev) => [
            ...markInFlightToolsErrored(prev, errorMsg),
            {
              role: "system",
              content: `Error: ${errorMsg}`,
              createdAt: new Date(),
            },
          ]);
        }
      } finally {
        // Detach run-event listeners on all paths (abort, error, success) —
        // post-run stragglers must not mutate display state.
        unbindRunEvents();
        // Detach trace listeners and flush the uploader on all paths
        // (abort, error, success).
        await runTrace.cleanupRun();
        if (gen === generationRef.current) {
          setStatus(pendingToolCallIdRef.current ? "waiting" : "idle");
          setThinking(false);
          setIsExecuting(false);
          abortControllerRef.current = null;

          // Show plan review after the full response is rendered
          if (planSubmittedRef.current) {
            planSubmittedRef.current = false;
            setShowPlanReview(true);
          }
        }
      }
    },
    [
      session,
      model.id,
      config.data,
      operatorState,
      operatorMode,
      agentMode,
      displayEvents,
      runEventProjections,
      setThinking,
      setIsExecuting,
      initialConfig?.sandbox,
      initialConfig?.taskDriven,
      initialConfig?.target,
      initialConfig?.headers,
      initialConfig?.promptInjectionLibrarySource,
      strikeMode,
      route.data,
      setSessionCwd,
      skillsRegistry.buildCatalog,
      requireApproval,
      skillsRegistry,
      reasoningEnabled,
      openAIReasoningEffort,
      usageStore,
      markExecuted,
    ],
  );

  const handleSubmit = useCallback(
    (value: string) => {
      const pending = approvalGateRef.current.getPendingApprovals();
      const result = resolveSubmit(value, status, pending.length > 0);

      if (result.denyPending) {
        for (const p of pending) {
          approvalGateRef.current.deny(p.id);
        }
      }

      // When agent is running, queue the message for later
      if (result.action === "blocked" && value.trim()) {
        setQueuedMessages((prev) => [
          ...prev,
          createQueuedMessage(value.trim()),
        ]);
        setInputValue("");
        return;
      }

      if (result.action !== "run" || !result.prompt) return;

      setInputValue("");
      runAgent(result.prompt);
    },
    [status, runAgent],
  );

  // Auto-send initial message once loading completes.
  // For new sessions, `session` is null until the first runAgent call creates
  // it via the agent factory, so we intentionally don't gate on `session`.
  const initialMessageSentRef = useRef(false);
  const runAgentRef = useRef(runAgent);
  runAgentRef.current = runAgent;
  useEffect(() => {
    if (!loading && initialMessage && !initialMessageSentRef.current) {
      initialMessageSentRef.current = true;
      runAgentRef.current(initialMessage);
    }
  }, [loading, initialMessage]);

  // Auto-submit initial skill once loading completes.
  // When the dashboard mounts with route.initialSkill set (e.g. from the
  // /threat-model command), load the skill content and send it to the agent
  // just as if the user had typed /<skill-slug>.
  const initialSkillSentRef = useRef(false);
  useEffect(() => {
    if (loading || initialSkillSentRef.current) return;
    const routeData = route.data;
    if (routeData.type !== "operator" || !routeData.initialSkill) return;

    initialSkillSentRef.current = true;
    const { slug, args } = routeData.initialSkill;

    (async () => {
      try {
        const { content } = await skillsRegistry.readSkillContent(slug);

        let fullContent: string;
        if (slug === "threat-model") {
          const outputPath = args?.output || "threat-model.md";
          const resolvedPath = isAbsolute(outputPath)
            ? outputPath
            : resolve(process.cwd(), outputPath);
          const basePrompt = buildThreatModelPrompt({
            outputPath: resolvedPath,
            codebasePath: process.cwd(),
            skillContent: content,
          });
          fullContent = `${basePrompt}

# Interactive Threat Model — Operator Workflow

You're running inside the Apex TUI with a human operator at the keyboard. Before generating the final threat model, follow this three-phase sequence:

## 1. Initial recon (≈10–20 tool calls)
Spend a small budget orienting yourself on the codebase before asking anything:
- List the repo root and any \`infra/\`, \`Dockerfile\`, \`docker-compose*\` files
- Read manifests (\`package.json\`, \`go.mod\`, \`Cargo.toml\`, \`requirements.txt\`, \`pom.xml\`, etc.)
- Skim auth modules and the primary API/route entry points
- Note the framework, deployment style, and any obvious external integrations

The point is to know enough to ask **grounded** questions — option labels in your batch should reference things you actually saw in the code, not generic templates.

## 2. Ask the operator for context
Once you have a baseline understanding, call \`ask_user_questions\` ONCE with 2–4 grounded questions covering the gaps your recon couldn't resolve. Prioritize:
- Deployment topology / runtime that the code didn't make obvious
- Sensitive data classification (PII, PCI, secrets, customer data)
- User / actor types and how they authenticate
- Trust boundaries (where untrusted input enters)
- Known security concerns or prior incidents the operator wants emphasized

Each option label MUST cite something concrete you observed (e.g. "AWS ECS Fargate (inferred from \`infra/ecs.ts\`)" — not "AWS deployment"). Skip categories that the recon already answered conclusively.

## 3. Continue with the threat model
After the operator submits answers (or skips), incorporate their input into the analysis and generate the threat model per the skill instructions above. The answers ARE part of the threat-model context — surface them where relevant in the output (e.g. data-sensitivity classifications inform the impact rating; user types inform the actor model).

If the operator skips the question batch, proceed with the recon-only context and do your best.

This three-phase flow is specific to the TUI \`/threat-model\` command. The same skill in headless / autonomous contexts skips phases 1–2 entirely (no \`ask_user_questions\` tool available there) and relies on the operator's prior context.`;
        } else if (slug === "pentest") {
          fullContent = buildPentestPrompt({
            target: args?.target || "",
            cwd: args?.cwd,
            authUrl: args?.["auth-url"],
            authUser: args?.["auth-user"],
            authPass: args?.["auth-pass"],
            authInstructions: args?.["auth-instructions"],
            hosts: args?.hosts?.split(",").filter(Boolean),
            ports: args?.ports?.split(",").filter(Boolean),
            strict: args?.strict === "true",
            prompt: args?.prompt,
            skillContent: content,
          });
        } else {
          const contextParts: string[] = [];
          if (args) {
            for (const [key, value] of Object.entries(args)) {
              const resolvedValue =
                key === "output" && !isAbsolute(value)
                  ? resolve(process.cwd(), value)
                  : value;
              contextParts.push(`${key}: ${resolvedValue}`);
            }
          }
          contextParts.push(`Working directory: ${process.cwd()}`);
          const runtimeContext = contextParts.join("\n");
          fullContent = `<skill name="${slug}">\n${runtimeContext}\n\n${content}\n</skill>`;
        }

        runAgentRef.current(fullContent);
      } catch {
        // Fallback: tell agent to load skill via tool
        runAgentRef.current(
          `Use the read_skill tool to load the "${slug}" skill and follow its instructions.`,
        );
      }
    })();
  }, [loading, route.data, skillsRegistry]);

  // Auto-send queued messages when agent becomes idle
  useEffect(() => {
    if (status !== "idle") return;
    const queue = queuedMessagesRef.current;
    if (queue.length === 0) return;

    const next = queue[0].text;
    setQueuedMessages((prev) => prev.slice(1));
    setSelectedQueueIndex(-1);
    runAgentRef.current(next);
  }, [status]);

  // Auto-run agent after plan approval (waits for mode transition to render)
  useEffect(() => {
    if (!planApprovedPendingRunRef.current) return;
    if (operatorMode === "plan") return;
    planApprovedPendingRunRef.current = false;
    runAgentRef.current("Proceed with the approved plan.");
  }, [operatorMode]);

  const addSystemMessage = useCallback((content: string) => {
    setMessages((prev) => [
      ...prev,
      { role: "system" as const, content, createdAt: new Date() },
    ]);
  }, []);

  const showModelPicker = useCallback(() => {
    executeCommand("/models");
  }, [executeCommand]);

  const handleHeadersSlash = useCallback(
    async (op: import("./logic").HeadersOp) => {
      const active = sessionRef.current;
      if (!active) {
        addSystemMessage("No active session — cannot manage headers yet.");
        return;
      }
      const current: Record<string, string> = {
        ...(active.config?.headers ?? {}),
      };

      const persist = async (next: Record<string, string>, message: string) => {
        const updated = await sessions.updateSessionHeaders(active.id, next);
        // Touch both ref and state — runAgent captures `session` in its
        // dep array, so a stale closure would skip the new headers.
        sessionRef.current = updated;
        setSession(updated);
        addSystemMessage(message);
      };

      switch (op.kind) {
        case "invalid": {
          addSystemMessage(`/headers: ${op.reason}`);
          return;
        }
        case "list": {
          const entries = Object.entries(current);
          if (entries.length === 0) {
            addSystemMessage("No session headers set.");
            return;
          }
          const lines = entries.map(
            ([name, value]) =>
              `${isSensitiveHeaderName(name) ? "* " : "  "}${name}: ${renderHeaderValue(name, value, op.showSecrets)}`,
          );
          addSystemMessage(
            `Session headers (${entries.length}):\n${lines.join("\n")}${op.showSecrets ? "" : "\nPass `/headers list --show` to reveal values."}`,
          );
          return;
        }
        case "add": {
          const parsed = parseHeaderLine(op.line);
          if (!parsed.ok) {
            addSystemMessage(
              `/headers add rejected:\n${formatParseError(parsed.error)}`,
            );
            return;
          }
          const canonical = Object.keys(current).find(
            (k) => k.toLowerCase() === parsed.value.name.toLowerCase(),
          );
          if (canonical && !op.allowOverwrite) {
            addSystemMessage(
              `Header "${canonical}" already set. Use \`/headers set\` to overwrite.`,
            );
            return;
          }
          if (canonical && canonical !== parsed.value.name) {
            delete current[canonical];
          }
          current[parsed.value.name] = parsed.value.value;
          await persist(
            current,
            `Header ${parsed.value.name} updated (value redacted).`,
          );
          return;
        }
        case "remove": {
          const canonical = Object.keys(current).find(
            (k) => k.toLowerCase() === op.name.toLowerCase(),
          );
          if (!canonical) {
            addSystemMessage(`No header named "${op.name}".`);
            return;
          }
          delete current[canonical];
          await persist(current, `Header ${canonical} removed.`);
          return;
        }
        case "clear": {
          if (Object.keys(current).length === 0) {
            addSystemMessage("Headers already empty.");
            return;
          }
          await persist({}, "All session headers cleared.");
          return;
        }
      }
    },
    [addSystemMessage],
  );

  const handleCommandExecute = useCallback(
    async (command: string) => {
      const action = routeCommand(command, resolveSkillContent);

      switch (action.type) {
        case "show-models":
          showModelPicker();
          return;
        case "run-skill": {
          if (
            strikeMode &&
            (action.slug === "pentest" || action.slug === "threat-model")
          ) {
            addSystemMessage(
              `/${action.slug} requires standard operator mode. Disable Strike Mode in /advanced, then start a new session.`,
            );
            return;
          }
          if (action.autopilot) {
            setOperatorMode("auto");
            approvalGateRef.current.updateConfig({ requireApproval: false });
            setOperatorState((prev) => ({ ...prev, requireApproval: false }));
          }
          // Load the skill's full instructions and send them to the agent
          // so it can act on the skill directly without an extra tool call.
          try {
            const { content } = await skillsRegistry.readSkillContent(
              action.slug,
            );
            let fullContent: string;
            if (action.slug === "threat-model") {
              const resolvedPath = resolve(process.cwd(), "threat-model.md");
              fullContent = buildThreatModelPrompt({
                outputPath: resolvedPath,
                codebasePath: process.cwd(),
                skillContent: content,
              });
            } else {
              const runtimeContext = `Working directory: ${process.cwd()}`;
              fullContent = `<skill name="${action.slug}">\n${runtimeContext}\n\n${content}\n</skill>`;
            }
            handleSubmit(fullContent);
          } catch {
            // Fallback: tell the agent to load the skill via tool
            handleSubmit(
              `Use the read_skill tool to load the "${action.slug}" skill and follow its instructions.`,
            );
          }
          return;
        }
        case "open-session": {
          const rootPath = sessionRef.current?.rootPath;
          if (rootPath) {
            openFileInDefaultApp(rootPath);
          } else {
            addSystemMessage("No active session to open.");
          }
          return;
        }
        case "show-plan": {
          const planContent = sessionRef.current
            ? readPlan(sessionRef.current.rootPath)
            : null;
          addSystemMessage(
            planContent
              ? `## Current Plan\n\n${planContent}`
              : "No plan exists yet. Switch to plan mode (Shift+Tab) to create one.",
          );
          return;
        }
        case "headers": {
          await handleHeadersSlash(action.op);
          return;
        }
        case "execute-command":
          await executeCommand(action.command);
          return;
      }
    },
    [
      resolveSkillContent,
      skillsRegistry,
      handleSubmit,
      executeCommand,
      showModelPicker,
      addSystemMessage,
      handleHeadersSlash,
      strikeMode,
    ],
  );

  const handleAbort = useCallback(() => {
    if (!abortControllerRef.current) return;

    const action = resolveAbortAction(commandCancelledRef.current, () =>
      cancelHandleRef.current.cancel(),
    );

    if (action.type === "cancel-command") {
      commandCancelledRef.current = true;
      setMessages((prev) => [
        ...prev,
        {
          role: "system" as const,
          content:
            "Command cancelled — agent will continue with partial output.",
          createdAt: new Date(),
        },
      ]);
      return;
    }

    // Kill the agent
    generationRef.current++;
    abortControllerRef.current.abort();
    abortControllerRef.current = null;
    commandCancelledRef.current = false;

    // Clear queued messages before setting idle to prevent auto-send
    setQueuedMessages([]);
    queuedMessagesRef.current = [];
    setSelectedQueueIndex(-1);

    // Deny pending approvals BEFORE resetting status.  denyAll() triggers
    // synchronous "approval-resolved" events whose handler calls
    // setStatus("running").  By calling denyAll() first, our setStatus("idle")
    // below is the last write in the React batch and wins.
    approvalGateRef.current.denyAll();

    setStatus("idle");
    setThinking(false);
    setIsExecuting(false);

    setMessages((prev) => markInFlightToolsErrored(prev, "Interrupted"));

    // Mark any in-flight subagent tool messages as interrupted too
    subagentStore.setState(markSubagentsInterrupted);

    // Read back persisted messages so the next run has full context.
    // Use sessionRef (not the `session` state) so we see the session even
    // when it was just created via onSessionReady but React hasn't
    // re-rendered yet (e.g. aborting on the very first message).
    const activeSession = sessionRef.current;
    if (activeSession) {
      conversationRef.current = recoverAbortedTranscript({
        rootPath: activeSession.rootPath,
        conversation: conversationRef.current,
        partialText: displayEvents.getPartialText(),
        displayMessages: displayMessagesRef.current,
      });
    }

    setMessages((prev) => {
      const updated = prev.map((m) =>
        isToolMessage(m) && (m.status === "pending" || m.status === "streaming")
          ? { ...m, status: "error" as const, result: "Cancelled by user" }
          : m,
      );
      return [
        ...updated,
        {
          role: "system" as const,
          content: "Agent stopped by user.",
          createdAt: new Date(),
        },
      ];
    });
  }, [setThinking, setIsExecuting, subagentStore.setState, displayEvents]);

  const resumeWithQuestionResult = useCallback(
    (result: AskUserQuestionsResult) => {
      const toolCallId = pendingToolCallIdRef.current;
      if (!toolCallId) return;

      // Bedrock Converse / Anthropic requires the { type: 'json', value }
      // wrapper around the answers payload.
      const updated = rewriteToolResultOutput(
        conversationRef.current,
        toolCallId,
        result as unknown as Record<string, unknown>,
      );

      conversationRef.current = updated;

      const activeSession = sessionRef.current;
      if (activeSession) {
        try {
          writeFileSync(
            join(activeSession.rootPath, "messages.json"),
            JSON.stringify(updated, null, 2),
          );
        } catch {
          // onStepFinish will overwrite shortly.
        }
      }

      pendingToolCallIdRef.current = null;
      setPendingQuestions(null);

      runAgentRef.current(null);
    },
    [],
  );

  const handleQuestionsSubmit = useCallback(
    (answers: AskUserQuestionAnswer[]) => {
      resumeWithQuestionResult({ answers, skipped: false });
    },
    [resumeWithQuestionResult],
  );

  const handleQuestionsSkip = useCallback(() => {
    resumeWithQuestionResult({ answers: [], skipped: true });
  }, [resumeWithQuestionResult]);

  // Complete a mode transition (shared by cycleMode and plan approval)
  const transitionToMode = useCallback((next: OperatorMode) => {
    approvalGateRef.current.updateConfig({
      requireApproval: next === "manual",
    });
    setOperatorState((s) => ({
      ...s,
      mode: next,
      requireApproval: next === "manual",
    }));
    setOperatorMode(next);

    // Persist mode so resumed sessions start in the correct mode
    const sid = sessionRef.current?.id;
    if (sid) {
      sessions
        .updateOperatorSettings(sid, { initialMode: next })
        .catch((e) => console.error("[operator] Failed to persist mode:", e));
    }
  }, []);

  // Cycle through operator modes: approvals-on → approvals-off → plan
  // Reads from refs to avoid stale closures — safe for rapid keypresses.
  const cycleMode = useCallback(() => {
    const current = operatorModeRef.current;
    const idx = OPERATOR_MODE_CYCLE.indexOf(current);
    const next = OPERATOR_MODE_CYCLE[(idx + 1) % OPERATOR_MODE_CYCLE.length];

    if (
      current === "plan" &&
      sessionRef.current &&
      hasPlan(sessionRef.current.rootPath) &&
      !approvedPlanRef.current &&
      !planGateBypassedOnResumeRef.current
    ) {
      setShowPlanReview(true);
      return;
    }

    if (next === "plan") {
      setApprovedPlanContent(null);
      planRejectedRef.current = false;
      planGateBypassedOnResumeRef.current = false;
    }

    transitionToMode(next);
  }, [transitionToMode]);

  // Keyboard shortcuts
  useKeyboard((key) => {
    // Queue navigation: handle before general shortcuts
    if (
      status === "running" &&
      queuedMessages.length > 0 &&
      !inputValue.trim()
    ) {
      if (key.name === "up") {
        key.preventDefault?.();
        setSelectedQueueIndex((prev) =>
          navigateUp(prev, queuedMessages.length),
        );
        return;
      }

      if (selectedQueueIndex >= 0) {
        if (key.name === "down") {
          key.preventDefault?.();
          setSelectedQueueIndex((prev) =>
            navigateDown(prev, queuedMessages.length),
          );
          return;
        }
        if (key.name === "backspace" || key.name === "delete") {
          key.preventDefault?.();
          const removeIdx = selectedQueueIndex;
          setQueuedMessages((prev) => prev.filter((_, i) => i !== removeIdx));
          setSelectedQueueIndex(() =>
            selectionAfterRemove(queuedMessages.length, removeIdx),
          );
          return;
        }
        if (key.name === "return") {
          key.preventDefault?.();
          const msg = queuedMessages[selectedQueueIndex].text;
          const removeIdx = selectedQueueIndex;
          setQueuedMessages((prev) => prev.filter((_, i) => i !== removeIdx));
          setSelectedQueueIndex(-1);

          displayEvents.flushCommandOutput();
          displayEvents.stopCommandOutputFlush();
          setMessages((prev) =>
            prev.map((m) =>
              isToolMessage(m) && m.status === "pending"
                ? { ...m, status: "error" as const, result: "Interrupted" }
                : m,
            ),
          );

          runAgentRef.current(msg);
          return;
        }
        if (key.raw === "e" || key.raw === "E") {
          key.preventDefault?.();
          const msg = queuedMessages[selectedQueueIndex].text;
          const removeIdx = selectedQueueIndex;
          setQueuedMessages((prev) => prev.filter((_, i) => i !== removeIdx));
          setInputValue(msg);
          setSelectedQueueIndex(-1);
          return;
        }
      }
    }

    if (showPlanReview && !inputValue.trim()) {
      if (key.name === "y" || key.raw === "Y") {
        key.preventDefault?.();
        const planContent = sessionRef.current
          ? readPlan(sessionRef.current.rootPath)
          : null;
        if (!planContent?.trim()) {
          setShowPlanReview(false);
          addSystemMessage("Plan file is missing or empty. Cannot approve.");
          return;
        }
        approvedPlanRef.current = planContent;
        planApprovedPendingRunRef.current = true;
        setApprovedPlanContent(planContent);
        setShowPlanReview(false);
        transitionToMode("manual");
        addSystemMessage("Plan approved. Executing plan.");
        return;
      }
      if (key.name === "n" || key.raw === "N") {
        key.preventDefault?.();
        planRejectedRef.current = true;
        setShowPlanReview(false);
        addSystemMessage(
          "Plan rejected. Refine the plan based on operator feedback.",
        );
        return;
      }
    }

    // Ctrl+C while questions are pending — abort without resuming the agent.
    // The abort controller is null at this point (runAgent's finally block
    // already cleared it), so handleAbort() would early-return. Handle it
    // explicitly: overwrite the sentinel tool-result so the next run doesn't
    // see stale "questions answered" data, then dismiss the form and go idle.
    if (pendingQuestions && key.ctrl && key.name === "c") {
      key.preventDefault?.();
      const toolCallId = pendingToolCallIdRef.current;
      if (toolCallId) {
        conversationRef.current = rewriteToolResultOutput(
          conversationRef.current,
          toolCallId,
          {
            answers: [],
            skipped: true,
            aborted: true,
          } as unknown as Record<string, unknown>,
        );
        const activeSession = sessionRef.current;
        if (activeSession) {
          try {
            writeFileSync(
              join(activeSession.rootPath, "messages.json"),
              JSON.stringify(conversationRef.current, null, 2),
            );
          } catch {
            /* onStepFinish will overwrite shortly */
          }
        }
      }
      pendingToolCallIdRef.current = null;
      setPendingQuestions(null);
      setStatus("idle");
      addSystemMessage("Aborted — questions dismissed.");
      return;
    }

    // Treat the questions form as a dialog so that dashboard-level shortcuts
    // (Shift+Tab cycle-mode, etc.) don't fire while the form owns the keyboard.
    const dialogOpen =
      stack.length > 0 || externalDialogOpen || !!pendingQuestions;

    // Ctrl+A to open subagent dialog (skip if another dialog is open)
    if (
      key.ctrl &&
      key.name === "a" &&
      subagentSessions.size > 0 &&
      !dialogOpen
    ) {
      key.preventDefault?.();
      openSubagentDialog();
      return;
    }

    // Ctrl+I to open the screenshot stack (no-op if no screenshots yet)
    if (key.ctrl && key.name === "i" && !dialogOpen) {
      const screenshots = collectScreenshotPaths(displayMessagesRef.current);
      if (screenshots.length === 0) return;
      key.preventDefault?.();
      replaceDialog(
        <ScreenshotModal screenshots={screenshots} onClose={clearDialog} />,
        { bare: true, selfHandlesEscape: true },
      );
      return;
    }
    const action = resolveKeyboardShortcut(
      key,
      status,
      inputValue,
      pendingApprovals.length > 0,
      dialogOpen,
    );

    switch (action.type) {
      case "skip":
        return;
      case "ctrl-c-abort":
        key.preventDefault?.();
        handleAbort();
        return;
      case "ctrl-c-clear":
        key.preventDefault?.();
        setInputValue("");
        return;
      case "escape":
        route.navigate({ type: "base", path: "home" });
        return;
      case "toggle-verbose":
        setVerboseMode((v) => !v);
        return;
      case "toggle-expanded-logs":
        setExpandedLogs((e) => !e);
        return;
      case "cycle-mode":
        cycleMode();
        return;
      case "approve":
        handleApprove();
        return;
      case "auto-approve":
        handleAutoApprove();
        return;
    }
  });

  // Show plan review prompt when triggered.
  // Guard ref prevents duplicate injection (e.g., React StrictMode double-fire).
  const planReviewInjectedRef = useRef(false);
  useEffect(() => {
    if (!showPlanReview) {
      planReviewInjectedRef.current = false;
      return;
    }
    if (planReviewInjectedRef.current || !sessionRef.current) return;
    const planContent = readPlan(sessionRef.current.rootPath);
    if (!planContent) {
      setShowPlanReview(false);
      return;
    }
    planReviewInjectedRef.current = true;
    setMessages((prev) => [
      ...prev,
      {
        role: "system" as const,
        content: "",
        createdAt: new Date(),
        isPlanReview: true,
        planContent,
      },
    ]);
  }, [showPlanReview]);

  // Loading state
  if (loading) {
    return (
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        alignItems="center"
        justifyContent="center"
      >
        <text fg={colors.textMuted}>Loading session...</text>
      </box>
    );
  }

  if (!session && error) {
    return (
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        alignItems="center"
        justifyContent="center"
        gap={1}
      >
        <text fg={colors.error}>Failed to load session</text>
        <text fg={colors.textMuted}>{error}</text>
        <text fg={colors.textMuted}>Press ESC to go back</text>
      </box>
    );
  }

  // Determine the current pending approval for the input area
  const currentPending =
    pendingApprovals.length > 0 ? pendingApprovals[0] : undefined;

  return (
    <box
      flexDirection="column"
      width="100%"
      height="100%"
      flexGrow={1}
      overflow="hidden"
    >
      {/* Header bar */}
      <box
        flexDirection="row"
        justifyContent="space-between"
        paddingLeft={2}
        paddingRight={2}
        paddingTop={1}
        paddingBottom={1}
        flexShrink={0}
      >
        <box flexDirection="row" gap={2}>
          <text fg={colors.text}>{session?.name ?? "New Session"}</text>
          {strikeMode && <text fg={colors.warning}>STRIKE</text>}
          {(session?.targets[0] || initialConfig?.target) && (
            <>
              <text fg={colors.textMuted}>•</text>
              <text fg={colors.textMuted}>
                {session?.targets[0] || initialConfig?.target || ""}
              </text>
            </>
          )}
        </box>
      </box>

      {/* Error banner */}
      {error && (
        <box paddingLeft={2} paddingRight={2} flexShrink={0}>
          <text fg={colors.error}>{error}</text>
        </box>
      )}

      {/* Message display */}
      <MessageList
        messages={messages}
        isRunning={
          (status === "running" || status === "waiting") && !pendingQuestions
        }
        variant="operator"
        focused={true}
        verbose={verboseMode}
        expandedLogs={expandedLogs}
        pendingApprovals={pendingApprovals}
        lastApprovedAction={lastApprovedAction}
      />

      <SubagentStatusBar
        sessions={subagentSessions}
        agentMovedOn={
          messageCountAtSubagentDoneRef.current !== null &&
          messages.length > messageCountAtSubagentDoneRef.current
        }
        onOpen={openSubagentDialog}
      />

      {pendingQuestions ? (
        <QuestionsForm
          questions={pendingQuestions}
          onSubmit={handleQuestionsSubmit}
          onSkip={handleQuestionsSkip}
        />
      ) : (
        <>
          <QueuedMessages
            messages={queuedMessages}
            selectedIndex={selectedQueueIndex}
          />

          <InputArea
            value={inputValue}
            onChange={setInputValue}
            onSubmit={
              showPlanReview
                ? (value: string) => {
                    const trimmed = value.trim();
                    if (!trimmed) return;
                    planRejectedRef.current = true;
                    setShowPlanReview(false);
                    handleSubmit(trimmed);
                  }
                : handleSubmit
            }
            placeholder={
              showPlanReview
                ? "Type feedback to refine, or Y to approve, N to reject..."
                : status === "running"
                  ? "Queue a follow-up message..."
                  : status === "waiting"
                    ? "Type to redirect agent, or Y/A to approve..."
                    : "Enter directive or / for commands & skills..."
            }
            focused={
              status === "running"
                ? selectedQueueIndex < 0
                : resolveInputFocused(status, stack.length, externalDialogOpen)
            }
            status={status === "waiting" ? "running" : status}
            mode="operator"
            operatorMode={operatorMode}
            pendingApproval={currentPending}
            onApprove={handleApprove}
            onAutoApprove={handleAutoApprove}
            enableAutocomplete={true}
            autocompleteOptions={autocompleteOptions}
            commandOptionMap={commandOptionMap}
            commandNames={commandNames}
            autocompletePlacement="above"
            enableCommands={true}
            onCommandExecute={handleCommandExecute}
            highlightSlashCommands={true}
            disableHistoryNavigation={
              status === "running" && queuedMessages.length > 0
            }
          />
        </>
      )}
    </box>
  );
}
