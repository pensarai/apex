/**
 * Operator Dashboard
 *
 * Interactive operator mode that uses the OffensiveSecurityAgent
 * with streaming message display and chat input.
 * Reuses MessageList and InputArea from the shared/chat components.
 */

import { useState, useEffect, useRef, useCallback } from "react";
import { useKeyboard } from "@opentui/react";

import { sessions, type SessionInfo } from "../../../core/session";
import { runOffensiveSecurityAgent } from "../../../core/api/offesecAgent";
import { buildAuthConfig } from "../../../core/ai/utils";
import { ALL_TOOL_NAMES } from "../../../core/agents/offSecAgent";
import { useAgent } from "../../context/agent";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { MessageList } from "../chat/message-list";
import { InputArea } from "../chat/input-area";
import { useTheme } from "../../theme";
import type { DisplayMessage } from "../agent-display";
import { isToolMessage } from "../shared/type-guards";
import type { OperatorMode, PendingApproval } from "../../../core/operator";
import {
  ApprovalGate,
  createInitialOperatorState,
  type OperatorSessionState,
} from "../../../core/operator";
import { stepCountIs } from "ai";

interface OperatorDashboardProps {
  sessionId: string;
  /** If true, restore saved state from disk instead of starting fresh */
  isResume?: boolean;
}

type DashboardStatus = "idle" | "running" | "waiting" | "done";

/**
 * Operator Dashboard - interactive chat interface with the offensive security agent
 */
export default function OperatorDashboard({
  sessionId,
  isResume = false,
}: OperatorDashboardProps) {
  const { colors } = useTheme();
  const route = useRoute();
  const config = useConfig();
  const { model, setThinking, setIsExecuting } = useAgent();

  // Session state
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Agent/status state
  const [status, setStatus] = useState<DashboardStatus>("idle");
  const abortControllerRef = useRef<AbortController | null>(null);

  // Messages — same pattern as pentest component
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const textRef = useRef("");

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

  // Load session on mount
  useEffect(() => {
    async function loadSession() {
      try {
        const s = await sessions.get(sessionId);
        setSession(s);

        // Load operator state if resuming
        if (isResume) {
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
            }
          }
        }

        // Initialize operator state from session config (only if not resuming)
        if (!isResume && s.config?.operatorSettings) {
          const settings = s.config.operatorSettings;
          const requireApproval = settings.requireApproval ?? true;
          const initialState = createInitialOperatorState(
            (settings.initialMode as OperatorMode) || "manual",
            requireApproval,
          );
          setOperatorState(initialState);
          approvalGateRef.current.updateConfig({ requireApproval });
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load session");
      } finally {
        setLoading(false);
      }
    }
    loadSession();
  }, [sessionId, isResume]);

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

      try {
        await runOffensiveSecurityAgent({
          system: buildOperatorSystemPrompt(session, operatorState),
          prompt,
          model: model.id,
          session,
          stopWhen: [stepCountIs(10000)],
          target: session.targets[0],
          activeTools: [...ALL_TOOL_NAMES],
          abortSignal: controller.signal,
          authConfig: buildAuthConfig(config.data),
          approvalGate: approvalGateRef.current,
          callbacks: {
            onTextDelta: (d) => {
              setThinking(false);
              appendText(d.text);
            },
            onToolCall: (d) => {
              setThinking(false);
              addToolCall(
                d.toolCallId,
                d.toolName,
                d.input as Record<string, unknown> | undefined,
              );
            },
            onToolResult: (d) => {
              setThinking(true);
              updateToolResult(d.toolCallId, d.toolName, d.output);
            },
            onError: (e) => {
              console.error("Agent error:", e);
              setError(e instanceof Error ? e.message : "Unknown error");
            },
          },
        });
      } catch (e) {
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
        setStatus("idle");
        setThinking(false);
        setIsExecuting(false);
        abortControllerRef.current = null;
      }
    },
    [
      session,
      model.id,
      config.data,
      operatorState,
      appendText,
      addToolCall,
      updateToolResult,
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

      if (status === "running") return;

      setInputValue("");
      runAgent(value.trim());
    },
    [status, runAgent],
  );

  const handleAbort = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
      setStatus("idle");
      setThinking(false);
      setIsExecuting(false);

      // Deny all pending approvals on abort
      approvalGateRef.current.denyAll();

      setMessages((prev) => [
        ...prev,
        {
          role: "system",
          content: "Agent stopped by user.",
          createdAt: new Date(),
        },
      ]);
    }
  }, [setThinking, setIsExecuting]);

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
    if (key.ctrl && key.name === "c") {
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
              : "Enter directive (e.g., 'Explore the attack surface')..."
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
