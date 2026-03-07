/**
 * Operator Dashboard
 *
 * Interactive operator mode that uses the OffensiveSecurityAgent
 * with streaming message display and chat input.
 * Reuses MessageList and InputArea from the shared/chat components.
 */

import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { useKeyboard } from "@opentui/react";

import {
  sessions,
  type SessionInfo,
  type SessionConfig,
} from "../../../core/session";
import { runOffensiveSecurityAgent } from "../../../core/api/offesecAgent";
import { buildAuthConfig } from "../../../core/ai/utils";
import {
  ALL_TOOL_NAMES,
  type ConsumeCallbacks,
} from "../../../core/agents/offSecAgent";
import {
  convertModelMessagesToUI,
  type UIMessage,
} from "../../../core/session/persistence";
import { useAgent } from "../../context/agent";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { useCommand } from "../../context/command";
import { useDialog } from "../../context/dialog";
import { MessageList } from "../chat/message-list";
import { InputArea } from "../chat/input-area";
import { useTheme } from "../../theme";
import type { DisplayMessage } from "../agent-display";
import { isToolMessage } from "../shared/type-guards";
import { getToolSummary } from "../shared/tool-registry";
import {
  tryParsePartialJson,
  extractStreamableContent,
} from "../shared/message-utils";
import type { OperatorMode, PendingApproval } from "../../../core/operator";
import { slugify } from "../../../core/skills";
import {
  ApprovalGate,
  createInitialOperatorState,
  type OperatorSessionState,
} from "../../../core/operator";
import {
  readExecutionMetrics,
  writeExecutionMetrics,
} from "../../../core/session/execution-metrics";
import { ModelPicker } from "../model-picker";
import { stepCountIs, type ModelMessage } from "ai";
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
import { QueuedMessages } from "./queued-messages";
import { navigateUp, navigateDown, selectionAfterRemove } from "./queue";
import { existsSync, readFileSync } from "fs";
import { join } from "path";

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
  initialConfig?: { requireApproval?: boolean; target?: string };
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
    resetTokenUsage,
    setSessionCwd,
  } = useAgent();
  const {
    autocompleteOptions: allAutocompleteOptions,
    executeCommand,
    resolveSkillContent,
    skills,
  } = useCommand();
  const {
    stack,
    externalDialogOpen,
    replace: showDialog,
    clear: clearDialog,
    setSize: setDialogSize,
  } = useDialog();

  const autocompleteOptions = useMemo(() => {
    const skillSlugs = new Set(skills.map((s) => `/${slugify(s.name)}`));
    return filterOperatorAutocomplete(allAutocompleteOptions, skillSlugs);
  }, [allAutocompleteOptions, skills]);

  // Session state
  const [session, setSession] = useState<SessionInfo | null>(null);
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

  // Messages — same pattern as pentest component
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
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
    new ApprovalGate({ requireApproval: true }),
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
              setOperatorState((prev) => ({
                ...prev,
                mode: (savedState.mode as OperatorMode) || prev.mode,
                requireApproval:
                  savedState.requireApproval ?? prev.requireApproval,
                currentStage:
                  (savedState.currentStage as OperatorSessionState["currentStage"]) ||
                  prev.currentStage,
              }));
              approvalGateRef.current.updateConfig({
                requireApproval: savedState.requireApproval ?? true,
              });

              if (
                Array.isArray(savedState.messages) &&
                savedState.messages.length > 0
              ) {
                const modelMsgs = savedState.messages;

                // Only pass a recent subset to the AI to avoid immediately
                // blowing the context window and triggering summarization.
                conversationRef.current = sessions.getResumeMessages(modelMsgs);

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
            }
          } else if (s.config?.operatorSettings) {
            const settings = s.config.operatorSettings;
            const requireApproval = settings.requireApproval ?? true;
            const initialState = createInitialOperatorState(
              (settings.initialMode as OperatorMode) || "manual",
              requireApproval,
            );
            setOperatorState(initialState);
            approvalGateRef.current.updateConfig({ requireApproval });
          }
        } else {
          // New session — just set up operator config; the agent creates the
          // session on the first runAgent call.
          const requireApproval = initialConfig?.requireApproval ?? true;
          const state = createInitialOperatorState("auto", requireApproval);
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

  useEffect(() => {
    if (!session) return;

    resetTokenUsage();
    tokenUsageRef.current = { inputTokens: 0, outputTokens: 0, totalTokens: 0 };

    const metrics = readExecutionMetrics(session.rootPath);
    const persisted = metrics?.tokenUsage;
    if (
      persisted &&
      (persisted.inputTokens > 0 || persisted.outputTokens > 0)
    ) {
      addTokenUsage(persisted.inputTokens, persisted.outputTokens);
      tokenUsageRef.current = persisted;
    }

    try {
      writeExecutionMetrics({
        sessionRootPath: session.rootPath,
        tokenUsage: tokenUsageRef.current,
      });
    } catch {
      // Best effort hydration write.
    }
  }, [session, addTokenUsage, resetTokenUsage]);

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
  // Per-subagent log management
  // ---------------------------------------------------------------------------

  const initSubagent = useCallback((subagentId: string, name?: string) => {
    setMessages((prev) => {
      const idx = prev.findLastIndex(
        (m) =>
          isToolMessage(m) &&
          (m.status === "pending" || m.status === "streaming"),
      );
      if (idx === -1) return prev;
      const msg = prev[idx];
      const subagentLogs = {
        ...(msg.subagentLogs ?? {}),
        [subagentId]: { name, status: "pending" as const, logs: [] },
      };
      const updated = [...prev];
      updated[idx] = { ...msg, subagentLogs };
      return updated;
    });
  }, []);

  const completeSubagent = useCallback(
    (subagentId: string, status: "completed" | "failed") => {
      setMessages((prev) => {
        const idx = prev.findLastIndex(
          (m) =>
            isToolMessage(m) &&
            (m.status === "pending" || m.status === "streaming"),
        );
        if (idx === -1) return prev;
        const msg = prev[idx];
        const entry = msg.subagentLogs?.[subagentId];
        if (!entry) return prev;
        const subagentLogs = {
          ...(msg.subagentLogs ?? {}),
          [subagentId]: { ...entry, status },
        };
        const updated = [...prev];
        updated[idx] = { ...msg, subagentLogs };
        return updated;
      });
    },
    [],
  );

  const appendLogToSubagent = useCallback(
    (subagentId: string, line: string) => {
      setMessages((prev) => {
        const idx = prev.findLastIndex(
          (m) =>
            isToolMessage(m) &&
            (m.status === "pending" || m.status === "streaming"),
        );
        if (idx === -1) return prev;
        const msg = prev[idx];
        const entry = msg.subagentLogs?.[subagentId];
        if (!entry) return prev;
        let logs = [...entry.logs, line];
        if (logs.length > MAX_LOG_LINES) {
          logs = logs.slice(-MAX_LOG_LINES);
        }
        const subagentLogs = {
          ...(msg.subagentLogs ?? {}),
          [subagentId]: { ...entry, logs },
        };
        const updated = [...prev];
        updated[idx] = { ...msg, subagentLogs };
        return updated;
      });
    },
    [],
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
    // Disable approval for the rest of the session
    approvalGateRef.current.updateConfig({ requireApproval: false });
    setOperatorState((prev) => ({ ...prev, requireApproval: false }));

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
    async (prompt: string) => {
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

      // Add user message
      setMessages((prev) => [
        ...prev,
        { role: "user", content: prompt, createdAt: new Date() },
      ]);

      // Build messages array — append user turn to conversation history.
      // Update conversationRef eagerly so the user turn survives an abort.
      const nextMessages: ModelMessage[] = [
        ...conversationRef.current,
        { role: "user", content: prompt },
      ];
      conversationRef.current = nextMessages;

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

      const callbacks = {
        onTextDelta: (d) => {
          setThinking(false);
          appendText(d.text);
        },
        onToolCallStreaming: (d) => {
          setThinking(false);
          addStreamingToolCall(d.toolCallId, d.toolName);
        },
        onToolCallDelta: (d) => {
          appendToolCallDelta(d.toolCallId, d.argsTextDelta);
        },
        onToolCall: (d) => {
          setThinking(false);
          commandCancelledRef.current = false;
          addToolCall(
            d.toolCallId,
            d.toolName,
            d.input as Record<string, unknown> | undefined,
          );
        },
        onToolResult: (d) => {
          flushCommandOutput();
          if (cmdFlushTimerRef.current) {
            clearInterval(cmdFlushTimerRef.current);
            cmdFlushTimerRef.current = null;
          }
          setThinking(true);
          updateToolResult(d.toolCallId, d.toolName, d.output);
        },
        onCommandOutput,
        onError: (e) => {
          console.error("Agent error:", e);
          setError(e instanceof Error ? e.message : "Unknown error");
        },
        subagentCallbacks: {
          onSubagentSpawn: ({ subagentId, name }) => {
            initSubagent(subagentId, name);
          },
          onSubagentComplete: ({ subagentId, status }) => {
            completeSubagent(subagentId, status);
          },
          onTextDelta: (_d) => {
            // Text deltas from sub-agents are omitted from per-subagent
            // windows — tool call summaries provide a cleaner activity log.
          },
          onToolCall: (d) => {
            if (!d.subagentId) return;
            const args =
              ((d as Record<string, unknown>).input as Record<
                string,
                unknown
              >) ?? {};
            const summary = getToolSummary(d.toolName, args);
            appendLogToSubagent(d.subagentId, summary);
          },
          onToolResult: (d) => {
            if (!d.subagentId) return;
            const args =
              ((d as Record<string, unknown>).args as Record<
                string,
                unknown
              >) ?? {};
            const summary = getToolSummary(d.toolName, args);
            appendLogToSubagent(d.subagentId, `✓ ${summary}`);
          },
          onError: (e) => {
            const msg = e instanceof Error ? e.message : "subagent error";
            appendLogToActiveTool(`✗ ${msg}`);
          },
        },
      } satisfies ConsumeCallbacks;

      const commonInput = {
        prompt,
        model: model.id,
        messages: nextMessages,
        stopWhen: [stepCountIs(10000)],
        target: initialConfig?.target,
        activeTools: [...ALL_TOOL_NAMES] as string[],
        abortSignal: controller.signal,
        authConfig: buildAuthConfig(config.data),
        approvalGate: approvalGateRef.current,
        commandCancelHandle: cancelHandleRef.current,
        onStepFinish,
        callbacks,
        onSessionReady: (s: { rootPath: string }) => {
          setSessionCwd(s.rootPath);
        },
      };

      try {
        let agentResult;

        if (session) {
          agentResult = await runOffensiveSecurityAgent({
            ...commonInput,
            system: buildOperatorSystemPrompt(
              initialConfig?.target,
              operatorState,
            ),
            session,
          });
        } else {
          // First call — let the agent factory create the session
          const requireApproval = initialConfig?.requireApproval ?? true;
          const sessionConfig: SessionConfig = {
            sessionType: "web-app",
            mode: "operator",
            operatorSettings: {
              initialMode: "auto",
              requireApproval,
              enableSuggestions: true,
            },
          };
          agentResult = await runOffensiveSecurityAgent({
            ...commonInput,
            system: buildOperatorSystemPrompt(
              initialConfig?.target,
              operatorState,
            ),
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

        // Persist full conversation for next turn
        try {
          const response = await agentResult.streamResult.response;
          if (gen === generationRef.current && response.messages) {
            conversationRef.current = [
              ...nextMessages,
              ...response.messages,
            ] as ModelMessage[];
          }
        } catch {
          // Stream may have been aborted; conversation stays as-is
        }
      } catch (e) {
        if (gen !== generationRef.current) return;
        if ((e as Error).name !== "AbortError") {
          const errorMsg = e instanceof Error ? e.message : "Agent failed";
          setError(errorMsg);
          setMessages((prev) => [
            ...prev,
            {
              role: "system",
              content: `Error: ${errorMsg}`,
              createdAt: new Date(),
            },
          ]);
        }
      } finally {
        if (gen === generationRef.current) {
          setStatus("idle");
          setThinking(false);
          setIsExecuting(false);
          abortControllerRef.current = null;
        }
      }
    },
    [
      session,
      model.id,
      config.data,
      operatorState,
      addTokenUsage,
      appendText,
      addStreamingToolCall,
      appendToolCallDelta,
      addToolCall,
      updateToolResult,
      flushCommandOutput,
      onCommandOutput,
      appendLogToActiveTool,
      initSubagent,
      completeSubagent,
      appendLogToSubagent,
      setThinking,
      setIsExecuting,
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

  const showModelPicker = useCallback(() => {
    setDialogSize("large");
    showDialog(
      <box flexDirection="column" width="100%" paddingLeft={4} paddingTop={1}>
        <text>
          <span fg={colors.primary}>█ </span>
          <span fg={colors.text}>Select AI Model</span>
          <span fg={colors.textMuted}> ({model.name})</span>
        </text>
        <box flexDirection="column" paddingLeft={2} marginTop={1}>
          <ModelPicker
            config={config.data}
            selectedModel={model}
            onSelectModel={setModel}
            onConfirm={clearDialog}
            onConfigUpdate={config.update}
            focused={true}
            isModelUserSelected={isModelUserSelected}
          />
        </box>
        <box marginTop={1} paddingLeft={2}>
          <text fg={colors.textMuted}>[Enter] confirm • [ESC] close</text>
        </box>
      </box>,
    );
  }, [
    colors,
    model,
    setModel,
    isModelUserSelected,
    config,
    showDialog,
    clearDialog,
    setDialogSize,
  ]);

  const handleCommandExecute = useCallback(
    async (command: string) => {
      const action = routeCommand(command, resolveSkillContent);

      switch (action.type) {
        case "show-models":
          showModelPicker();
          return;
        case "run-skill":
          if (action.autopilot) {
            approvalGateRef.current.updateConfig({ requireApproval: false });
            setOperatorState((prev) => ({ ...prev, requireApproval: false }));
          }
          handleSubmit(action.content);
          return;
        case "execute-command":
          await executeCommand(action.command);
          return;
      }
    },
    [resolveSkillContent, handleSubmit, executeCommand, showModelPicker],
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

    setStatus("idle");
    setThinking(false);
    setIsExecuting(false);

    approvalGateRef.current.denyAll();

    // Read back persisted messages so the next run has full context.
    // Only keep a recent subset to avoid blowing the context window.
    if (session) {
      try {
        const messagesPath = join(session.rootPath, "messages.json");
        if (existsSync(messagesPath)) {
          const raw = JSON.parse(readFileSync(messagesPath, "utf-8"));
          if (Array.isArray(raw) && raw.length > 0) {
            conversationRef.current = sessions.getResumeMessages(
              raw as ModelMessage[],
            );
          }
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
  }, [session, setThinking, setIsExecuting]);

  // Toggle approval requirement at runtime
  const toggleApproval = useCallback(() => {
    setOperatorState((prev) => {
      const newVal = !prev.requireApproval;
      approvalGateRef.current.updateConfig({ requireApproval: newVal });
      return { ...prev, requireApproval: newVal };
    });
  }, []);

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

    const dialogOpen = stack.length > 0 || externalDialogOpen;
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
      case "toggle-approval":
        toggleApproval();
        return;
      case "approve":
        handleApprove();
        return;
      case "auto-approve":
        handleAutoApprove();
        return;
    }
  });

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
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
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
          <text fg={colors.primary}>Operator</text>
          <text fg={colors.textMuted}>•</text>
          <text fg={colors.text}>{session?.name ?? "New Session"}</text>
          {(session?.targets[0] || initialConfig?.target) && (
            <>
              <text fg={colors.textMuted}>•</text>
              <text fg={colors.textMuted}>
                {session?.targets[0] || initialConfig?.target}
              </text>
            </>
          )}
        </box>
        <box flexDirection="row" gap={2}>
          <text
            fg={operatorState.requireApproval ? colors.warning : colors.primary}
          >
            {operatorState.requireApproval ? "APPROVAL ON" : "APPROVAL OFF"}
          </text>
          <text fg={colors.textMuted}>{model.name}</text>
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
        isRunning={status === "running" || status === "waiting"}
        variant="operator"
        focused={true}
        verbose={verboseMode}
        expandedLogs={expandedLogs}
        pendingApprovals={pendingApprovals}
        lastApprovedAction={lastApprovedAction}
      />

      {/* Queued follow-up messages */}
      <QueuedMessages
        messages={queuedMessages}
        selectedIndex={selectedQueueIndex}
      />

      {/* Input area */}
      <InputArea
        value={inputValue}
        onChange={setInputValue}
        onSubmit={handleSubmit}
        placeholder={
          status === "running"
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
        operatorMode={operatorState.mode}
        verboseMode={verboseMode}
        expandedLogs={expandedLogs}
        pendingApproval={currentPending}
        onApprove={handleApprove}
        onAutoApprove={handleAutoApprove}
        enableAutocomplete={true}
        autocompleteOptions={autocompleteOptions}
        enableCommands={true}
        onCommandExecute={handleCommandExecute}
        disableHistoryNavigation={
          status === "running" && queuedMessages.length > 0
        }
      />
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
