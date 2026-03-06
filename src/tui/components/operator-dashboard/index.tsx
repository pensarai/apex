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
import { generateRandomName } from "../../../util/name";
import { buildAuthConfig } from "../../../core/ai/utils";
import { ALL_TOOL_NAMES } from "../../../core/agents/offSecAgent";
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
import { isTerminalCopyShortcut, shouldHandleOperatorCtrlC } from "./keyboard";
import { existsSync, readFileSync } from "fs";
import { join } from "path";

type DashboardStatus = "idle" | "running" | "waiting" | "done";

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
  initialConfig?: { requireApproval?: boolean };
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
    const allowedCommands = new Set(["/create-skill", "/models"]);
    const skillSlugs = new Set(skills.map((s) => `/${slugify(s.name)}`));
    return allAutocompleteOptions.filter(
      (opt) => allowedCommands.has(opt.value) || skillSlugs.has(opt.value),
    );
  }, [allAutocompleteOptions, skills]);

  // Session state
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  // Load or create session on mount
  useEffect(() => {
    async function loadSession() {
      try {
        let s: SessionInfo;

        if (sessionId) {
          s = await sessions.get(sessionId);
        } else {
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
          s = await sessions.create({
            targets: [],
            name: generateRandomName(),
            config: sessionConfig,
          });

          const state = createInitialOperatorState("auto", requireApproval);
          setOperatorState(state);
          approvalGateRef.current.updateConfig({ requireApproval });
        }

        setSession(s);

        // For existing sessions, attempt to load saved operator state
        if (sessionId) {
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
                conversationRef.current = modelMsgs;

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

  const addToolCall = useCallback(
    (toolCallId: string, toolName: string, args?: Record<string, unknown>) => {
      textRef.current = "";
      setMessages((prev) => [
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
      ]);
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
        (m) => isToolMessage(m) && m.status === "pending",
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
        (m) => isToolMessage(m) && m.status === "pending",
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
      if (!session) return;

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

      try {
        const streamResult = await runOffensiveSecurityAgent({
          system: buildOperatorSystemPrompt(session, operatorState),
          prompt,
          model: model.id,
          session,
          messages: nextMessages,
          stopWhen: [stepCountIs(10000)],
          target: session.targets[0],
          activeTools: [...ALL_TOOL_NAMES],
          abortSignal: controller.signal,
          authConfig: buildAuthConfig(config.data),
          approvalGate: approvalGateRef.current,
          commandCancelHandle: cancelHandleRef.current,
          onStepFinish: (event) => {
            const inputTokens = event.usage?.inputTokens ?? 0;
            const outputTokens = event.usage?.outputTokens ?? 0;
            if (inputTokens <= 0 && outputTokens <= 0) return;

            const nextUsage = {
              inputTokens: tokenUsageRef.current.inputTokens + inputTokens,
              outputTokens: tokenUsageRef.current.outputTokens + outputTokens,
              totalTokens:
                tokenUsageRef.current.totalTokens + inputTokens + outputTokens,
            };
            tokenUsageRef.current = nextUsage;

            addTokenUsage(inputTokens, outputTokens);
            try {
              writeExecutionMetrics({
                sessionRootPath: session.rootPath,
                tokenUsage: nextUsage,
              });
            } catch {
              // Best effort: token metrics should not interrupt operator runs.
            }
          },
          callbacks: {
            onTextDelta: (d) => {
              setThinking(false);
              appendText(d.text);
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
              onSubagentSpawn: ({ subagentId }) => {
                appendLogToActiveTool(`▸ ${subagentId} started`);
              },
              onSubagentComplete: ({ subagentId, status }) => {
                const icon = status === "completed" ? "✓" : "✗";
                appendLogToActiveTool(`${icon} ${subagentId} ${status}`);
              },
              onTextDelta: (d) => {
                if (!d.subagentId) return;
                onCommandOutput(d.text);
              },
              onToolCall: (d) => {
                if (!d.subagentId) return;
                const args =
                  ((d as Record<string, unknown>).input as Record<
                    string,
                    unknown
                  >) ?? {};
                const summary = getToolSummary(d.toolName, args);
                appendLogToActiveTool(summary);
              },
              onToolResult: (d) => {
                if (!d.subagentId) return;
                const args =
                  ((d as Record<string, unknown>).args as Record<
                    string,
                    unknown
                  >) ?? {};
                const summary = getToolSummary(d.toolName, args);
                appendLogToActiveTool(`✓ ${summary}`);
              },
              onError: (e) => {
                const msg = e instanceof Error ? e.message : "subagent error";
                appendLogToActiveTool(`✗ ${msg}`);
              },
            },
          },
        });

        // Persist full conversation for next turn
        try {
          const response = await streamResult.response;
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
      addToolCall,
      updateToolResult,
      flushCommandOutput,
      onCommandOutput,
      appendLogToActiveTool,
      setThinking,
      setIsExecuting,
    ],
  );

  const handleSubmit = useCallback(
    (value: string) => {
      if (!value.trim()) return;

      // If there's a pending approval and the user types, deny and redirect
      const pending = approvalGateRef.current.getPendingApprovals();
      if (pending.length > 0) {
        for (const p of pending) {
          approvalGateRef.current.deny(p.id);
        }
      }

      // Block submission only when the agent is actively running (not waiting)
      if (status === "running") return;

      setInputValue("");
      runAgent(value.trim());
    },
    [status, runAgent],
  );

  // Auto-send initial message once the session finishes loading
  const initialMessageSentRef = useRef(false);
  const runAgentRef = useRef(runAgent);
  runAgentRef.current = runAgent;
  useEffect(() => {
    if (
      !loading &&
      session &&
      initialMessage &&
      !initialMessageSentRef.current
    ) {
      initialMessageSentRef.current = true;
      runAgentRef.current(initialMessage);
    }
  }, [loading, session, initialMessage]);

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
      const commandLower = command.trim().replace(/^\/+/, "").toLowerCase();

      // /models — show model picker dialog inline
      if (commandLower === "models" || commandLower === "model") {
        showModelPicker();
        return;
      }

      // Detect and strip --autopilot flag before resolving
      const autopilot = command.includes("--autopilot");
      const cleanedCommand = command.replace(/\s*--autopilot\s*/g, "").trim();

      const skillContent = resolveSkillContent(cleanedCommand);
      if (skillContent) {
        if (autopilot) {
          approvalGateRef.current.updateConfig({ requireApproval: false });
          setOperatorState((prev) => ({ ...prev, requireApproval: false }));
        }
        handleSubmit(skillContent);
        return;
      }
      await executeCommand(command);
    },
    [resolveSkillContent, handleSubmit, executeCommand, showModelPicker],
  );

  const handleAbort = useCallback(() => {
    if (!abortControllerRef.current) return;

    // Stage 1: If a command is running and hasn't been cancelled yet,
    // cancel just the command and let the agent continue.
    if (!commandCancelledRef.current && cancelHandleRef.current.cancel()) {
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

    // Stage 2: No command running, or second Ctrl+C — kill the agent.
    generationRef.current++;
    abortControllerRef.current.abort();
    abortControllerRef.current = null;
    commandCancelledRef.current = false;
    setStatus("idle");
    setThinking(false);
    setIsExecuting(false);

    approvalGateRef.current.denyAll();

    // Read back persisted messages so the next run has full context
    if (session) {
      try {
        const messagesPath = join(session.rootPath, "messages.json");
        if (existsSync(messagesPath)) {
          const raw = JSON.parse(readFileSync(messagesPath, "utf-8"));
          if (Array.isArray(raw) && raw.length > 0) {
            conversationRef.current = raw as ModelMessage[];
          }
        }
      } catch {
        // Best-effort — keep whatever conversationRef already has
      }
    }

    setMessages((prev) => {
      const updated = prev.map((m) =>
        isToolMessage(m) && m.status === "pending"
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
    // Skip local shortcuts when dialogs are open (e.g. shortcuts popup)
    if (stack.length > 0 || externalDialogOpen) return;

    // Let terminal-native copy shortcuts pass through so selected output text
    // in operator mode can still be copied.
    if (isTerminalCopyShortcut(key)) {
      return;
    }

    if (shouldHandleOperatorCtrlC(key, status, inputValue)) {
      key.preventDefault?.();
      if (status === "running" || status === "waiting") {
        handleAbort();
      } else if (inputValue.trim()) {
        setInputValue("");
      }
      return;
    }

    if (key.name === "escape" && status !== "running" && status !== "waiting") {
      route.navigate({ type: "base", path: "home" });
      return;
    }

    // Ctrl+V - toggle verbose mode
    if (key.ctrl && key.name === "v") {
      setVerboseMode((v) => !v);
      return;
    }

    // Ctrl+L - toggle expanded logs
    if (key.ctrl && key.name === "l") {
      setExpandedLogs((e) => !e);
      return;
    }

    // Shift+Tab - toggle command approval on/off
    if (key.name === "tab" && key.shift) {
      toggleApproval();
      return;
    }

    // Y/y to approve pending
    if (
      status === "waiting" &&
      pendingApprovals.length > 0 &&
      (key.name === "y" || key.raw === "Y")
    ) {
      handleApprove();
      return;
    }

    // A/a to auto-approve (disable approval)
    if (
      status === "waiting" &&
      pendingApprovals.length > 0 &&
      (key.name === "a" || key.raw === "A")
    ) {
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

  if (!session) {
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
        {error && <text fg={colors.textMuted}>{error}</text>}
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
          <text fg={colors.text}>{session.name}</text>
          {session.targets[0] && (
            <>
              <text fg={colors.textMuted}>•</text>
              <text fg={colors.textMuted}>{session.targets[0]}</text>
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

      {/* Input area */}
      <InputArea
        value={inputValue}
        onChange={setInputValue}
        onSubmit={handleSubmit}
        placeholder={
          status === "running"
            ? "Agent is working..."
            : status === "waiting"
              ? "Type to redirect agent, or Y/A to approve..."
              : "Enter directive or / for commands & skills..."
        }
        focused={status !== "running"}
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
      />
    </box>
  );
}

/**
 * Build a system prompt that includes operator context
 */
function buildOperatorSystemPrompt(
  session: SessionInfo,
  operatorState: OperatorSessionState,
): string {
  const target = session.targets[0] || "unknown";

  return `You are an offensive security agent operating in interactive operator mode.

Target: ${target}
Stage: ${operatorState.currentStage}
Command approval: ${operatorState.requireApproval ? "enabled — the operator will approve each tool call" : "disabled — tool calls execute automatically"}

You are tasked with performing security testing on the target system. The human operator
will guide your actions through directives. Follow their instructions carefully.

Guidelines:
- Be thorough and methodical in your testing approach
- Document all findings clearly
- Respect scope constraints
- Report any interesting observations, even if not directly exploitable
- When you discover credentials, endpoints, or vulnerabilities, note them clearly

Session paths:
- Findings: ${session.findingsPath}
- POCs: ${session.pocsPath}
- Logs: ${session.logsPath}
- Scratchpad: ${session.scratchpadPath}`;
}

// Re-export types for backward compatibility
export type {
  Endpoint,
  VerifiedVuln,
  Credential,
  Hypothesis,
  Evidence,
} from "./types";
