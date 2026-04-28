/**
 * Operator Dashboard
 *
 * Interactive operator mode that uses the OffensiveSecurityAgent
 * with streaming message display and chat input.
 * Reuses MessageList and InputArea from the shared/chat components.
 */

import {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
  useSyncExternalStore,
} from "react";
import { useKeyboard } from "@opentui/react";

import {
  sessions,
  type SessionInfo,
  type SessionConfig,
  normalizeMessages,
} from "../../../core/session";
import { runOffensiveSecurityAgent } from "../../../core/api/offesecAgent";
import { attachWandbToEventBus } from "../../../core/integrations/wandb/upload";
import { buildAuthConfig } from "../../../core/ai/utils";
import { modelSupportsThinking, type CacheMetrics } from "../../../core/ai";
import {
  ALL_TOOL_NAMES,
  PLAN_MODE_TOOL_NAMES,
  SKILL_TOOL_NAMES,
  ASK_USER_QUESTIONS_TOOL_NAME,
  AgentEventBus,
  type AgentMode,
} from "../../../core/agents/offSecAgent";
import {
  readPlan,
  hasPlan,
  planFilePath as getPlanFilePath,
} from "../../../core/plan";
import {
  convertModelMessagesToUI,
  type UIMessage,
} from "../../../core/session/persistence";
import { useAgent } from "../../context/agent";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { useCommand } from "../../context/command";
import { useDialog } from "../../context/dialog";
import { useFocus } from "../../context/focus";
import { MessageList } from "../chat/message-list";
import { InputArea } from "../chat/input-area";
import { useTheme } from "../../theme";
import type { DisplayMessage, WorkflowData } from "../agent-display";
import { isToolMessage } from "../shared/type-guards";
import {
  tryParsePartialJson,
  extractStreamableContent,
} from "../shared/message-utils";
import type { OperatorMode, PendingApproval } from "../../../core/operator";
import {
  ApprovalGate,
  createInitialOperatorState,
  OPERATOR_MODE_CYCLE,
  type OperatorSessionState,
} from "../../../core/operator";
import {
  readExecutionMetrics,
  writeExecutionMetrics,
} from "../../../core/session/execution-metrics";
import { hasToolCall, stepCountIs, type ModelMessage } from "ai";
import type {
  AskUserQuestion,
  AskUserQuestionAnswer,
  AskUserQuestionsResult,
} from "../../../core/agents/offSecAgent/tools/askUserQuestions";
import { QuestionsForm } from "../chat/questions-form";
import {
  type DashboardStatus,
  filterOperatorAutocomplete,
  resolveSubmit,
  routeCommand,
  resolveKeyboardShortcut,
  resolveAbortAction,
  buildOperatorSystemPrompt,
  resolveInputFocused,
  accumulateTokenUsage,
} from "./logic";
import {
  createSubagentSessionHelpers,
  createSubagentStore,
  loadSubagentSessionsFromDisk,
} from "./subagent-state";
import { QueuedMessages } from "./queued-messages";
import { SubagentStatusBar } from "./subagent-status-bar";
import SubagentDialog from "./subagent-dialog";
import { navigateUp, navigateDown, selectionAfterRemove } from "./queue";
import { openFileInDefaultApp } from "../../utils/open-file.js";
import { existsSync, readFileSync, writeFileSync } from "fs";
import { isAbsolute, join, resolve } from "path";

import { buildThreatModelPrompt } from "../../../core/skills/builtins/threatModel";
import { buildPentestPrompt } from "../../../core/skills/builtins/pentest";
import { obfuscate } from "../../../core/obfuscation";

function markInFlightToolsErrored(
  messages: DisplayMessage[],
  result: string,
): DisplayMessage[] {
  return messages.map((m) =>
    isToolMessage(m) && (m.status === "pending" || m.status === "streaming")
      ? { ...m, status: "error" as const, result }
      : m,
  );
}

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
    sandbox?: boolean;
    taskDriven?: boolean;
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
    addTokenUsage,
    addCacheUsage,
    resetTokenUsage,
    setSessionCwd,
    reasoningEnabled,
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
  const { stack, externalDialogOpen, replace: replaceDialog } = useDialog();
  const { refocusPrompt } = useFocus();

  const autocompleteOptions = useMemo(() => {
    const commandOptions = filterOperatorAutocomplete(allAutocompleteOptions);
    const skillOptions = skillsRegistry.list().map((s) => {
      const slug = `/${s.slug}`;
      return {
        value: slug,
        label: slug,
        description: s.manifest.description || "Skill",
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
  }, [allAutocompleteOptions, skillsRegistry, skillsVersion]);

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
  const textRef = useRef("");
  // AI SDK conversation history for multi-turn continuity
  const conversationRef = useRef<ModelMessage[]>([]);
  // Input state
  const [inputValue, setInputValue] = useState("");

  // Queued follow-up messages
  const [queuedMessages, setQueuedMessages] = useState<string[]>([]);
  const [selectedQueueIndex, setSelectedQueueIndex] = useState(-1);
  const queuedMessagesRef = useRef<string[]>([]);

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
  const agentMode: AgentMode = operatorMode === "plan" ? "plan" : "default";
  const requireApproval = operatorMode === "manual";
  // Plan mode review state
  const [approvedPlanContent, setApprovedPlanContent] = useState<string | null>(
    null,
  );
  const [showPlanReview, setShowPlanReview] = useState(false);
  const planSubmittedRef = useRef(false);
  const planRejectedRef = useRef(false);
  const planApprovedPendingRunRef = useRef(false);

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
  const tokenUsageRef = useRef(tokenUsage);

  useEffect(() => {
    tokenUsageRef.current = tokenUsage;
  }, [tokenUsage]);

  // Subscribe to approval gate events
  useEffect(() => {
    const gate = approvalGateRef.current;

    const onApprovalNeeded = () => {
      setPendingApprovals(gate.getPendingApprovals());
      setStatus("waiting");
    };

    const onApprovalResolved = (event: { id: string; decision: string }) => {
      setPendingApprovals(gate.getPendingApprovals());
      if (event.decision === "approved") {
        setLastApprovedAction(event.id);
      }
      if (gate.getPendingApprovals().length === 0) {
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

              // Restore plan content from a prior session so the cycleMode
              // gate doesn't force a redundant re-approval on Shift+Tab.
              // Only mark the plan as approved if the user previously left
              // plan mode (restoredMode !== "plan"), which signals prior approval.
              if (restoredMode !== "plan") {
                const planContent = readPlan(s.rootPath);
                if (planContent) {
                  setApprovedPlanContent(planContent);
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
  }, [sessionId]);

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
    // Only run the reset / hydrate cycle for *resumed* sessions (those
    // with a `sessionId` prop). Brand-new sessions reach this effect after
    // their first agent step has already accumulated tokens via
    // `addTokenUsage`, and a reset here would wipe that initial usage.
    if (!session || !sessionId) return;

    resetTokenUsage();
    tokenUsageRef.current = {
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      cachedTokens: 0,
      cacheWriteTokens: 0,
    };

    const metrics = readExecutionMetrics(session.rootPath);
    const persisted = metrics?.tokenUsage;
    if (
      persisted &&
      (persisted.inputTokens > 0 || persisted.outputTokens > 0)
    ) {
      addTokenUsage(persisted.inputTokens, persisted.outputTokens);
      tokenUsageRef.current = {
        ...persisted,
        cachedTokens: 0,
        cacheWriteTokens: 0,
      };
    }

    try {
      writeExecutionMetrics({
        sessionRootPath: session.rootPath,
        tokenUsage: tokenUsageRef.current,
      });
    } catch {
      // Best effort hydration write.
    }
  }, [session, sessionId, addTokenUsage, resetTokenUsage]);

  // ---------------------------------------------------------------------------
  // Message helpers — same pattern as pentest component
  // ---------------------------------------------------------------------------

  const appendText = useCallback((text: string) => {
    textRef.current += text;
    const accumulated = textRef.current;
    setMessages((prev) => {
      const last = prev[prev.length - 1];
      if (last && last.role === "assistant") {
        const updated = [...prev];
        updated[updated.length - 1] = { ...last, content: accumulated };
        return updated;
      }
      return [
        ...prev,
        { role: "assistant", content: accumulated, createdAt: new Date() },
      ];
    });
  }, []);

  // Ref to accumulate partial tool args JSON per toolCallId
  const toolArgsDeltaRef = useRef<
    Map<string, { toolName: string; accumulated: string }>
  >(new Map());

  const addStreamingToolCall = useCallback(
    (toolCallId: string, toolName: string) => {
      textRef.current = "";
      toolArgsDeltaRef.current.set(toolCallId, {
        toolName,
        accumulated: "",
      });
      setMessages((prev) => [
        ...prev,
        {
          role: "tool" as const,
          content: "",
          createdAt: new Date(),
          toolCallId,
          toolName,
          args: {},
          status: "streaming" as const,
        },
      ]);
    },
    [],
  );

  const appendToolCallDelta = useCallback(
    (toolCallId: string, argsTextDelta: string) => {
      const entry = toolArgsDeltaRef.current.get(toolCallId);
      const accumulated = (entry?.accumulated ?? "") + argsTextDelta;
      toolArgsDeltaRef.current.set(toolCallId, {
        toolName: entry?.toolName ?? "",
        accumulated,
      });

      const parsed = tryParsePartialJson(accumulated);
      if (!parsed) return;

      const contentText = extractStreamableContent(parsed);
      const logs = contentText ? contentText.split("\n") : undefined;

      setMessages((msgs) => {
        const idx = msgs.findIndex(
          (m) => isToolMessage(m) && m.toolCallId === toolCallId,
        );
        if (idx === -1) return msgs;
        const updated = [...msgs];
        updated[idx] = { ...updated[idx], args: parsed, ...(logs && { logs }) };
        return updated;
      });
    },
    [],
  );

  const addToolCall = useCallback(
    (toolCallId: string, toolName: string, args?: Record<string, unknown>) => {
      textRef.current = "";
      toolArgsDeltaRef.current.delete(toolCallId);
      setMessages((prev) => {
        const idx = prev.findIndex(
          (m) => isToolMessage(m) && m.toolCallId === toolCallId,
        );
        if (idx !== -1) {
          const updated = [...prev];
          updated[idx] = {
            ...updated[idx],
            args,
            logs: undefined,
            status: "pending" as const,
          };
          return updated;
        }
        return [
          ...prev,
          {
            role: "tool" as const,
            content: "",
            createdAt: new Date(),
            toolCallId,
            toolName,
            args,
            status: "pending" as const,
          },
        ];
      });
    },
    [],
  );

  const updateToolResult = useCallback(
    (toolCallId: string, _toolName: string, result?: unknown) => {
      textRef.current = "";
      setMessages((prev) => {
        const idx = prev.findIndex(
          (m) => isToolMessage(m) && m.toolCallId === toolCallId,
        );
        if (idx === -1) return prev;
        const updated = [...prev];
        updated[idx] = { ...updated[idx], status: "completed", result };
        return updated;
      });
    },
    [],
  );

  // ---------------------------------------------------------------------------
  // Streaming command output — throttled to avoid excessive re-renders
  // ---------------------------------------------------------------------------

  const cmdOutputBufRef = useRef("");
  const cmdFlushTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const MAX_LOG_LINES = 200;

  const flushCommandOutput = useCallback(() => {
    const buf = cmdOutputBufRef.current;
    if (!buf) return;
    cmdOutputBufRef.current = "";

    setMessages((prev) => {
      const idx = prev.findLastIndex(
        (m) =>
          isToolMessage(m) &&
          (m.status === "pending" || m.status === "streaming"),
      );
      if (idx === -1) return prev;

      const msg = prev[idx];
      const existing = msg.logs ?? [];
      const incoming = buf.split("\n");
      // If last existing line was partial (no trailing newline), merge it
      let merged: string[];
      if (existing.length > 0 && !buf.startsWith("\n")) {
        merged = [...existing];
        merged[merged.length - 1] += incoming[0];
        merged.push(...incoming.slice(1));
      } else {
        merged = [...existing, ...incoming];
      }
      // Cap to last MAX_LOG_LINES
      if (merged.length > MAX_LOG_LINES) {
        merged = merged.slice(-MAX_LOG_LINES);
      }

      const updated = [...prev];
      updated[idx] = { ...msg, logs: merged };
      return updated;
    });
  }, []);

  const onCommandOutput = useCallback(
    (data: string) => {
      cmdOutputBufRef.current += data;

      if (!cmdFlushTimerRef.current) {
        cmdFlushTimerRef.current = setInterval(() => {
          flushCommandOutput();
        }, 150);
      }
    },
    [flushCommandOutput],
  );

  // Clean up the flush timer when the component unmounts or agent stops
  useEffect(() => {
    return () => {
      if (cmdFlushTimerRef.current) {
        clearInterval(cmdFlushTimerRef.current);
        cmdFlushTimerRef.current = null;
      }
    };
  }, []);

  // ---------------------------------------------------------------------------
  // Subagent activity — append log lines to the active (pending) tool message
  // ---------------------------------------------------------------------------

  const appendLogToActiveTool = useCallback((line: string) => {
    setMessages((prev) => {
      const idx = prev.findLastIndex(
        (m) =>
          isToolMessage(m) &&
          (m.status === "pending" || m.status === "streaming"),
      );
      if (idx === -1) return prev;

      const msg = prev[idx];
      let logs = [...(msg.logs ?? []), line];
      if (logs.length > MAX_LOG_LINES) {
        logs = logs.slice(-MAX_LOG_LINES);
      }
      const updated = [...prev];
      updated[idx] = { ...msg, logs };
      return updated;
    });
  }, []);

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

      setStatus("running");
      setThinking(true);
      setIsExecuting(true);
      setError(null);
      textRef.current = "";

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

      const onStepFinish = (event: {
        usage?: { inputTokens?: number; outputTokens?: number };
      }) => {
        const nextUsage = accumulateTokenUsage(
          tokenUsageRef.current,
          event.usage?.inputTokens ?? 0,
          event.usage?.outputTokens ?? 0,
        );
        if (!nextUsage) return;
        tokenUsageRef.current = nextUsage;

        addTokenUsage(
          event.usage?.inputTokens ?? 0,
          event.usage?.outputTokens ?? 0,
        );
        if (session) {
          try {
            writeExecutionMetrics({
              sessionRootPath: session.rootPath,
              tokenUsage: nextUsage,
            });
          } catch {
            // Best effort: token metrics should not interrupt operator runs.
          }
        }
      };

      const eventBus = new AgentEventBus();

      // Only pentest swarm agents (pentest-agent-*) get entries in
      // WorkflowData.pentesting.subagents. All others (discovery, risk
      // scorers, whitebox analyzers) are excluded.
      const isPentestAgent = (id?: string) =>
        id !== undefined && /^pentest-agent-\d+$/.test(id);

      // Patch the workflowData on the active run_pentest_workflow tool message.
      const updateWorkflowData = (
        updater: (wd: WorkflowData) => WorkflowData,
      ) => {
        setMessages((prev) => {
          const idx = prev.findLastIndex(
            (m) =>
              isToolMessage(m) &&
              m.toolName === "run_pentest_workflow" &&
              (m.status === "pending" || m.status === "streaming"),
          );
          if (idx === -1) return prev;
          const msg = prev[idx];
          const wd = msg.workflowData ?? {
            currentPhase: "discovery" as const,
            discovery: { label: "", status: "pending" as const, logs: [] },
            pentesting: {
              label: "",
              status: "idle" as const,
              subagents: {},
            },
            reporting: { label: "", status: "idle" as const },
          };
          const updated = [...prev];
          updated[idx] = { ...msg, workflowData: updater(wd) };
          return updated;
        });
      };

      eventBus.on("text-delta", (d) => {
        if (gen !== generationRef.current) return;
        if (d.subagentId) {
          subagentHelpers.appendText(d.subagentId, d.text);
          return;
        }
        setThinking(false);
        appendText(d.text);
      });

      eventBus.on("tool-call-start", (d) => {
        if (gen !== generationRef.current) return;
        if (d.subagentId) {
          subagentHelpers.addStreamingToolCall(
            d.subagentId,
            d.toolCallId,
            d.toolName,
          );
          return;
        }
        setThinking(false);
        addStreamingToolCall(d.toolCallId, d.toolName);
      });

      eventBus.on("tool-call-delta", (d) => {
        if (gen !== generationRef.current) return;
        if (d.subagentId) {
          subagentHelpers.appendToolCallDelta(
            d.subagentId,
            d.toolCallId,
            d.argsTextDelta,
          );
          return;
        }
        appendToolCallDelta(d.toolCallId, d.argsTextDelta);
      });

      eventBus.on("tool-call-complete", (d) => {
        if (gen !== generationRef.current) return;
        if (d.subagentId) {
          const args =
            d.args &&
            typeof d.args === "object" &&
            !Array.isArray(d.args) &&
            d.args !== null
              ? (d.args as Record<string, unknown>)
              : {};
          subagentHelpers.addToolCall(
            d.subagentId,
            d.toolCallId,
            d.toolName,
            args,
          );
          return;
        }
        setThinking(false);
        commandCancelledRef.current = false;
        const args =
          d.args &&
          typeof d.args === "object" &&
          !Array.isArray(d.args) &&
          d.args !== null
            ? (d.args as Record<string, unknown>)
            : undefined;
        addToolCall(d.toolCallId, d.toolName, args);

        if (d.toolName === ASK_USER_QUESTIONS_TOOL_NAME && args) {
          const rawQuestions = args.questions;
          if (Array.isArray(rawQuestions) && rawQuestions.length > 0) {
            pendingToolCallIdRef.current = d.toolCallId;
            setPendingQuestions(rawQuestions as AskUserQuestion[]);
          }
        }
      });

      eventBus.on("tool-result", (d) => {
        if (gen !== generationRef.current) return;
        if (d.subagentId) {
          subagentHelpers.updateToolResult(
            d.subagentId,
            d.toolCallId,
            d.result,
          );
          return;
        }
        flushCommandOutput();
        if (cmdFlushTimerRef.current) {
          clearInterval(cmdFlushTimerRef.current);
          cmdFlushTimerRef.current = null;
        }
        setThinking(true);
        updateToolResult(d.toolCallId, d.toolName, d.result);

        // Track submit_plan success — review triggers after the run completes
        if (
          d.toolName === "submit_plan" &&
          (d.result as Record<string, unknown> | null)?.success === true
        ) {
          planSubmittedRef.current = true;
        }
      });

      eventBus.on("command-output", (d) => {
        if (gen !== generationRef.current) return;
        if (d.subagentId) return;
        onCommandOutput(d.data);
      });

      eventBus.on("error", (d) => {
        if (gen !== generationRef.current) return;
        if (d.subagentId) {
          const errMsg =
            d.error instanceof Error ? d.error.message : "Unknown error";
          subagentHelpers.appendText(d.subagentId, `\nError: ${errMsg}\n`);
          return;
        }
        console.error("Agent error:", d.error);
        // Clear pending-questions state so an error after the tool-call event
        // doesn't leave the questions form stuck over a failed conversation.
        pendingToolCallIdRef.current = null;
        setPendingQuestions(null);
        const errorMessage =
          d.error instanceof Error ? d.error.message : "Unknown error";
        setError(errorMessage);
        setMessages((prev) => markInFlightToolsErrored(prev, errorMessage));
      });

      eventBus.on("subagent-spawn", ({ subagentId, name }) => {
        if (gen !== generationRef.current) return;
        subagentHelpers.spawnSession(subagentId, name);
        if (!isPentestAgent(subagentId)) return;
        // Pentest swarm agents → workflowData.pentesting.subagents
        updateWorkflowData((wd) => ({
          ...wd,
          pentesting: {
            ...wd.pentesting,
            subagents: {
              ...wd.pentesting.subagents,
              [subagentId]: {
                name,
                status: "pending" as const,
                logs: [],
              },
            },
          },
        }));
      });

      eventBus.on("subagent-complete", ({ subagentId, status }) => {
        if (gen !== generationRef.current) return;
        subagentHelpers.completeSession(subagentId, status);
        if (!isPentestAgent(subagentId)) return;
        // Update workflowData swarm status
        updateWorkflowData((wd) => {
          const entry = wd.pentesting.subagents[subagentId];
          if (!entry) return wd;
          return {
            ...wd,
            pentesting: {
              ...wd.pentesting,
              subagents: {
                ...wd.pentesting.subagents,
                [subagentId]: { ...entry, status },
              },
            },
          };
        });
      });

      // Workflow phase events → update workflowData on the tool message
      eventBus.on("workflow-phase-start", (d) => {
        if (gen !== generationRef.current) return;
        textRef.current = "";
        // New workflow run — clear old subagent sessions so the hub
        // shows only the current batch.
        if (d.phase === "discovery") {
          subagentStore.setState(new Map());
        }
        updateWorkflowData((wd) => {
          const next = {
            ...wd,
            currentPhase: d.phase as WorkflowData["currentPhase"],
          };
          if (d.phase === "discovery") {
            next.discovery = {
              ...wd.discovery,
              label: d.label,
              status: "pending",
              logs: [],
            };
          } else if (d.phase === "pentesting") {
            next.pentesting = {
              ...wd.pentesting,
              label: d.label,
              status: "pending",
            };
          } else if (d.phase === "reporting") {
            next.reporting = {
              ...wd.reporting,
              label: d.label,
              status: "pending",
            };
          }
          return next;
        });
      });

      eventBus.on("workflow-phase-complete", (d) => {
        if (gen !== generationRef.current) return;
        textRef.current = "";
        updateWorkflowData((wd) => {
          const next = { ...wd };
          if (d.phase === "discovery") {
            const targets = (d.summary.targets ?? []) as {
              target: string;
              objectives: string[];
            }[];
            next.discovery = {
              ...wd.discovery,
              status: "complete",
              targets,
              cached: d.summary.cached as boolean | undefined,
            };
          } else if (d.phase === "pentesting") {
            next.pentesting = { ...wd.pentesting, status: "complete" };
          } else if (d.phase === "reporting") {
            next.reporting = {
              ...wd.reporting,
              status: "complete",
              findingsCount: d.summary.findingsCount as number | undefined,
              findingsBySeverity: d.summary.findingsBySeverity as
                | Record<string, number>
                | undefined,
              reportPath: d.summary.reportPath as string | undefined,
            };
            next.currentPhase = "complete";
          }
          return next;
        });
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
        onStepFinish,
        onCacheMetrics: (metrics: CacheMetrics) => {
          addCacheUsage(
            metrics.cacheReadInputTokens,
            metrics.cacheCreationInputTokens,
          );
        },
        eventBus,
        onSessionReady: (s: SessionInfo) => {
          setSessionCwd(s.rootPath);
          sessionRef.current = s;
          setSession((prev) => prev ?? s);
          tryAttachWandb(s);
        },
      };

      // W&B trace upload — buffer early records so none are lost for new sessions.
      // For resumed sessions, we attach before the agent starts.
      // For new sessions, onSessionReady fires mid-construction; we replay
      // any buffered records once the handler attaches.
      type TraceEvent = {
        record: import("../../../core/agents/offSecAgent/trace").TraceRecord;
        subagentId?: string;
      };
      let wandbCleanup: (() => Promise<void>) | null = null;
      let earlyBuffer: TraceEvent[] | null = [];

      const earlyBufferHandler = (e: TraceEvent) => {
        earlyBuffer?.push(e);
      };
      eventBus.on("trace-record", earlyBufferHandler);

      const tryAttachWandb = async (s: SessionInfo) => {
        if (wandbCleanup) return;
        const cleanup = await attachWandbToEventBus(s, eventBus).catch(
          (e: unknown) => {
            console.error("[wandb] Attach failed:", e);
            return null;
          },
        );
        if (cleanup) {
          wandbCleanup = cleanup;
          // Replay any records captured before the handler attached
          const buffered = earlyBuffer;
          earlyBuffer = null;
          eventBus.off("trace-record", earlyBufferHandler);
          if (buffered) {
            for (const e of buffered) {
              eventBus.emit("trace-record", e);
            }
          }
        } else {
          earlyBuffer = null;
          eventBus.off("trace-record", earlyBufferHandler);
        }
      };

      const wandbSession = session ?? sessionRef.current;
      if (wandbSession) {
        await tryAttachWandb(wandbSession);
      }

      try {
        let agentResult;

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
            },
            agentCwd: initialConfig?.sandbox ? undefined : process.cwd(),
            taskDriven: initialConfig?.taskDriven,
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
        // Clean up early buffer listener on all paths (abort, error, success)
        earlyBuffer = null;
        eventBus.off("trace-record", earlyBufferHandler);

        if (wandbCleanup) {
          const fn = wandbCleanup as () => Promise<void>;
          await fn().catch((e: unknown) =>
            console.error("[wandb] Flush failed:", e),
          );
        }
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
      addTokenUsage,
      appendText,
      addStreamingToolCall,
      appendToolCallDelta,
      addToolCall,
      updateToolResult,
      flushCommandOutput,
      onCommandOutput,
      appendLogToActiveTool,
      subagentHelpers,
      setThinking,
      setIsExecuting,
      addCacheUsage,
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
        setQueuedMessages((prev) => [...prev, value.trim()]);
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

    const next = queue[0];
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

  const handleCommandExecute = useCallback(
    async (command: string) => {
      const action = routeCommand(command, resolveSkillContent);

      switch (action.type) {
        case "show-models":
          showModelPicker();
          return;
        case "run-skill": {
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
    subagentStore.setState((prev) => {
      let changed = false;
      const next = new Map(prev);
      for (const [id, session] of next) {
        const hasInFlight = session.messages.some(
          (m) =>
            m.role === "tool" &&
            (m.status === "pending" || m.status === "streaming"),
        );
        if (hasInFlight || session.status === "running") {
          changed = true;
          next.set(id, {
            ...session,
            status: session.status === "running" ? "cancelled" : session.status,
            messages: session.messages.map((m) =>
              m.role === "tool" &&
              (m.status === "pending" || m.status === "streaming")
                ? { ...m, status: "error" as const, result: "Interrupted" }
                : m,
            ),
          });
        }
      }
      return changed ? next : prev;
    });

    // Read back persisted messages so the next run has full context.
    // Only keep a recent subset to avoid blowing the context window.
    // Use sessionRef (not the `session` state) so we see the session even
    // when it was just created via onSessionReady but React hasn't
    // re-rendered yet (e.g. aborting on the very first message).
    const activeSession = sessionRef.current;
    if (activeSession) {
      try {
        const messagesPath = join(activeSession.rootPath, "messages.json");
        if (existsSync(messagesPath)) {
          const raw = JSON.parse(readFileSync(messagesPath, "utf-8"));
          if (Array.isArray(raw) && raw.length > 0) {
            conversationRef.current = normalizeMessages(
              sessions.getResumeMessages(raw as ModelMessage[]),
            );
          }
        }

        // If the conversation now ends with a user message it means the agent
        // was aborted before completing its first inference step (onStepFinish
        // never fired, so no assistant turn was persisted).  Reconstruct the
        // partial assistant response — including any in-flight tool calls — so
        // the context survives abort and session resume.
        const last =
          conversationRef.current[conversationRef.current.length - 1];
        if (last?.role === "user") {
          const partial = textRef.current.trim();

          // Collect pending/streaming tool calls from the UI messages.
          const pendingTools = displayMessagesRef.current.filter(
            (m) =>
              isToolMessage(m) &&
              (m.status === "pending" || m.status === "streaming"),
          );

          // Build assistant content parts: text + tool-call entries.
          const assistantContent: Array<Record<string, unknown>> = [
            {
              type: "text" as const,
              text: partial || "[Response interrupted by user.]",
            },
          ];
          for (const t of pendingTools) {
            assistantContent.push({
              type: "tool-call" as const,
              toolCallId: t.toolCallId,
              toolName: t.toolName,
              input: t.args ?? {},
            });
          }

          conversationRef.current = [
            ...conversationRef.current,
            {
              role: "assistant" as const,
              content: assistantContent,
            } as ModelMessage,
          ];

          // For each tool call, add a tool-result so the conversation stays
          // valid (every tool-call must be paired with a tool-result).
          if (pendingTools.length > 0) {
            conversationRef.current = [
              ...conversationRef.current,
              {
                role: "tool" as const,
                content: pendingTools.map((t) => ({
                  type: "tool-result" as const,
                  toolCallId: t.toolCallId,
                  toolName: t.toolName ?? "unknown",
                  output: {
                    type: "text" as const,
                    value: "Cancelled by user.",
                  },
                })),
              } as unknown as ModelMessage,
            ];
          }

          // Persist so session resume also sees the corrected state.
          writeFileSync(
            join(activeSession.rootPath, "messages.json"),
            JSON.stringify(conversationRef.current, null, 2),
          );
        }
      } catch {
        // Best-effort — keep whatever conversationRef already has
      }
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
  }, [setThinking, setIsExecuting]);

  const resumeWithQuestionResult = useCallback(
    (result: AskUserQuestionsResult) => {
      const toolCallId = pendingToolCallIdRef.current;
      if (!toolCallId) return;

      // Bedrock Converse / Anthropic requires { type: 'json', value: ... } wrapper.
      const wrappedOutput = {
        type: "json" as const,
        value: result as unknown as Record<string, unknown>,
      };

      const updated: ModelMessage[] = conversationRef.current.map((msg) => {
        if (msg.role !== "tool") return msg;
        if (!Array.isArray(msg.content)) return msg;
        let mutated = false;
        const nextContent = msg.content.map((part) => {
          if (
            part &&
            typeof part === "object" &&
            "type" in part &&
            (part as { type?: unknown }).type === "tool-result" &&
            (part as { toolCallId?: unknown }).toolCallId === toolCallId
          ) {
            mutated = true;
            return {
              ...(part as Record<string, unknown>),
              output: wrappedOutput,
            };
          }
          return part;
        });
        return mutated
          ? ({ ...msg, content: nextContent } as ModelMessage)
          : msg;
      });

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

    // Gate: if leaving plan mode and a plan exists but isn't approved, show review
    if (
      current === "plan" &&
      sessionRef.current &&
      hasPlan(sessionRef.current.rootPath) &&
      !approvedPlanRef.current
    ) {
      setShowPlanReview(true);
      return;
    }

    // Entering plan mode — reset plan state for fresh cycle
    if (next === "plan") {
      setApprovedPlanContent(null);
      planRejectedRef.current = false;
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
          const msg = queuedMessages[selectedQueueIndex];
          const removeIdx = selectedQueueIndex;
          setQueuedMessages((prev) => prev.filter((_, i) => i !== removeIdx));
          setSelectedQueueIndex(-1);

          flushCommandOutput();
          if (cmdFlushTimerRef.current) {
            clearInterval(cmdFlushTimerRef.current);
            cmdFlushTimerRef.current = null;
          }
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
          const msg = queuedMessages[selectedQueueIndex];
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
        const abortedResult = {
          type: "json" as const,
          value: {
            answers: [],
            skipped: true,
            aborted: true,
          } as unknown as Record<string, unknown>,
        };
        conversationRef.current = conversationRef.current.map((msg) => {
          if (msg.role !== "tool" || !Array.isArray(msg.content)) return msg;
          let mutated = false;
          const nextContent = msg.content.map((part) => {
            if (
              part &&
              typeof part === "object" &&
              "type" in part &&
              (part as { type?: unknown }).type === "tool-result" &&
              (part as { toolCallId?: unknown }).toolCallId === toolCallId
            ) {
              mutated = true;
              return {
                ...(part as Record<string, unknown>),
                output: abortedResult,
              };
            }
            return part;
          });
          return mutated
            ? ({ ...msg, content: nextContent } as ModelMessage)
            : msg;
        });
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
          <text fg={colors.text}>
            {obfuscate(session?.name ?? "New Session")}
          </text>
          {(session?.targets[0] || initialConfig?.target) && (
            <>
              <text fg={colors.textMuted}>•</text>
              <text fg={colors.textMuted}>
                {obfuscate(session?.targets[0] || initialConfig?.target || "")}
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

// Re-export types for backward compatibility
export type {
  Endpoint,
  VerifiedVuln,
  Credential,
  Hypothesis,
  Evidence,
} from "./types";
