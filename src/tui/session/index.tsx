/**
 * Unified Session Component
 *
 * Single component handling both "chat" and "operator" modes.
 * Consolidates ChatView and OperatorDashboard into one implementation.
 *
 * Uses existing infrastructure:
 * - SessionProvider for session data
 * - AgentProvider for model/tokens
 * - useMessageState for O(1) message updates
 *
 * Features:
 * - Mode-aware layout (sidebar visible in operator mode)
 * - Inline approval rendering
 * - Streaming message support
 * - State persistence for resume
 */

import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { useKeyboard } from "@opentui/react";
import { Session } from "../../core/session";
import { createOperatorAgent, type OperatorAgent } from "../../core/agent/operatorAgent";
import type {
  OperatorMode,
  OperatorStage,
  PermissionTier,
  PendingApproval,
  ActionHistoryEntry,
} from "../../core/operator";
import { OPERATOR_STAGES, OPERATOR_MODES, PERMISSION_TIERS, getStagesInOrder } from "../../core/operator";
import { useRoute } from "../context/route";
import { useInput } from "../context/input";
import { useFocus } from "../context/focus";
import { useAgent } from "../context/agent";
import { colors } from "../theme";
import type { DisplayMessage } from "../components/agent-display";
import { isToolMessage, useMessageState } from "../components/shared";
import type { ModelInfo } from "../../core/ai";
import type { Endpoint, VerifiedVuln, Credential, Hypothesis, Evidence } from "../components/operator-dashboard/types";
import ToolsPanel from "../components/tools-panel";
import type { ToolsetState } from "../../core/toolset";

// Session sub-components
import { Header } from "../components/chat/header";
import { MessageList } from "../components/chat/message-list";
import { InputArea } from "../components/chat/input-area";
import { Sidebar, useSidebarState, type SidebarState } from "../components/chat/sidebar";

// ============================================
// Types
// ============================================

export interface SessionProps {
  /** Session info */
  session: Session.SessionInfo;
  /** Display mode */
  mode: "chat" | "operator";
  /** Model to use (if not using AgentProvider default) */
  model?: ModelInfo;
  /** If true, restore saved state from disk instead of starting fresh */
  isResume?: boolean;
  /** Initial directive to send when agent is ready */
  initialDirective?: string;
  /** Callback when exiting session */
  onExit?: () => void;
}

// ============================================
// Helper Functions
// ============================================

/**
 * Parse port from target URL or IP:port string
 */
function parsePortFromTarget(target: string): number | null {
  try {
    const url = new URL(target);
    if (url.port) return parseInt(url.port, 10);
    if (url.protocol === "https:") return 443;
    if (url.protocol === "http:") return 80;
  } catch {
    const match = target.match(/:(\d+)$/);
    if (match) return parseInt(match[1], 10);
  }
  return null;
}

/**
 * Extract hostname from target URL
 */
function parseHostFromTarget(target: string): string {
  try {
    const url = new URL(target);
    return url.hostname;
  } catch {
    return target.replace(/:(\d+)$/, "");
  }
}

// ============================================
// Main Component
// ============================================

export function SessionComponent({
  session,
  mode,
  model: propModel,
  isResume = false,
  initialDirective,
  onExit,
}: SessionProps) {
  const route = useRoute();
  const { model: agentModel, addTokenUsage, tokenUsage } = useAgent();
  const { setInputValue } = useInput();

  // Use ref to ensure agent always has access to latest callback
  const addTokenUsageRef = useRef(addTokenUsage);
  addTokenUsageRef.current = addTokenUsage;

  // Use provided model or fall back to agent context
  const model = propModel || agentModel;

  // Get Operator settings from session config
  const operatorSettings = session.config?.operatorSettings || {
    initialMode: "manual" as OperatorMode,
    autoApproveTier: 2 as PermissionTier,
  };

  // ============================================
  // Agent State
  // ============================================

  const [agent, setAgent] = useState<OperatorAgent | null>(null);
  const {
    messages,
    addMessage,
    updateTool,
    updateByIndex,
    setMessages,
    hasPendingTool,
  } = useMessageState();
  const [status, setStatus] = useState<string>("idle");
  const [streamingMessageIndex, setStreamingMessageIndex] = useState<number>(-1);

  // ============================================
  // Operator State
  // ============================================

  const [operatorMode, setOperatorMode] = useState<OperatorMode>(
    operatorSettings.initialMode
  );
  const [autoApproveTier, setAutoApproveTier] = useState<PermissionTier>(
    operatorSettings.autoApproveTier as PermissionTier
  );
  const [currentStage, setCurrentStage] = useState<OperatorStage>("setup");
  const [pendingApprovals, setPendingApprovals] = useState<PendingApproval[]>([]);
  const [actionHistory, setActionHistory] = useState<ActionHistoryEntry[]>([]);

  // Pre-computed stats counters
  const [approvedCount, setApprovedCount] = useState(0);
  const [deniedCount, setDeniedCount] = useState(0);

  // ============================================
  // UI State
  // ============================================

  const [directiveInput, setDirectiveInput] = useState("");
  const [showStageMenu, setShowStageMenu] = useState(false);
  const [showToolsPanel, setShowToolsPanel] = useState(false);
  const [verboseMode, setVerboseMode] = useState(false);
  const [expandedLogs, setExpandedLogs] = useState(false);
  const { refocusPrompt } = useFocus();
  const [lastApprovedAction, setLastApprovedAction] = useState<string | null>(null);
  const [lastDeclineNote, setLastDeclineNote] = useState<string | null>(null);
  const [resumeLoaded, setResumeLoaded] = useState(false);

  // Sync directive input with global input context
  useEffect(() => {
    setInputValue(directiveInput);
  }, [directiveInput, setInputValue]);

  // ============================================
  // Sidebar State
  // ============================================

  const sidebar = useSidebarState(session.id);

  // Parse host and port from target URL
  const targetHost = parseHostFromTarget(session.targets[0] || "");
  const initialPort = parsePortFromTarget(session.targets[0] || "");

  // Initialize sidebar with target info
  useEffect(() => {
    if (targetHost) {
      sidebar.updateState({
        targetHost,
        ports: initialPort ? [{ port: initialPort, service: "http" }] : [],
      });
    }
  }, [targetHost, initialPort]);

  // ============================================
  // State Gathering for Persistence
  // ============================================

  const gatherOperatorState = useCallback((): Session.OperatorSessionState => ({
    mode: operatorMode,
    autoApproveTier,
    currentStage,
    messages,
    attackSurface: sidebar.state.attackSurface,
    credentials: sidebar.state.credentials,
    verifiedVulns: sidebar.state.verifiedVulns,
    targetState: { host: targetHost, ports: sidebar.state.ports },
    hypotheses: [],
    evidence: [],
    actionHistory,
    pausedAt: new Date().toISOString(),
    lastRunId: agent?.currentRunId || "",
  }), [
    operatorMode, autoApproveTier, currentStage, messages,
    sidebar.state, targetHost, actionHistory, agent,
  ]);

  // ============================================
  // Resume State Loading
  // ============================================

  useEffect(() => {
    if (!isResume || resumeLoaded) return;

    Session.loadOperatorState(session.id).then((savedState) => {
      if (savedState) {
        setOperatorMode(savedState.mode as OperatorMode);
        setAutoApproveTier(savedState.autoApproveTier as PermissionTier);
        setCurrentStage(savedState.currentStage as OperatorStage);

        // Deserialize messages with proper date conversion
        const restoredMessages = (savedState.messages || []).map((msg: any) => ({
          ...msg,
          createdAt: msg.createdAt ? new Date(msg.createdAt) : new Date(),
          status: msg.role === "tool" && msg.status === "pending" ? "completed" : msg.status,
        }));
        setMessages(restoredMessages);

        // Restore sidebar state
        sidebar.updateState({
          attackSurface: savedState.attackSurface || [],
          credentials: savedState.credentials || [],
          verifiedVulns: savedState.verifiedVulns || [],
          ports: savedState.targetState?.ports || [],
        });

        setActionHistory(savedState.actionHistory || []);
        const history = savedState.actionHistory || [];
        setApprovedCount(
          history.filter((a: any) => a.decision === "approved" || a.decision === "auto-approved").length
        );
        setDeniedCount(history.filter((a: any) => a.decision === "denied").length);
      }
      setResumeLoaded(true);
    });
  }, [isResume, session.id, resumeLoaded, setMessages, sidebar]);

  // ============================================
  // Agent Initialization
  // ============================================

  useEffect(() => {
    if (agent) return;
    if (isResume && !resumeLoaded) return;

    const operatorAgent = createOperatorAgent({
      session,
      model: model.id,
      initialMode: operatorMode,
      autoApproveTier,
      initialStage: currentStage,
      previousMessages: isResume ? messages.map((m) => ({ ...m })) : undefined,
      previousAttackSurface: isResume
        ? sidebar.state.attackSurface.map((e) => ({
            method: e.method,
            path: e.path,
            status: e.status,
            category: e.category,
          }))
        : undefined,
      onTokenUsage: (input, output) => addTokenUsageRef.current(input, output),
    });

    // Status change
    operatorAgent.on("status-change", (newStatus: string) => {
      setStatus(newStatus);
    });

    // New message
    operatorAgent.on("message", (message: DisplayMessage) => {
      addMessage(message);
      if (message.role === "assistant") {
        setStreamingMessageIndex(messages.length);
        setLastApprovedAction(null);
      }
    });

    // Message update
    operatorAgent.on("message-updated", ({ index, message }: { index: number; message: DisplayMessage }) => {
      if (isToolMessage(message)) {
        updateTool(message.toolCallId, {
          status: message.status,
          result: message.result,
          logs: message.logs,
        });
      } else {
        // Update assistant/system messages by index
        updateByIndex(index, message);
      }
    });

    // Operator events
    operatorAgent.on("operator-event", (event: any) => {
      switch (event.type) {
        case "mode-changed":
          setOperatorMode(event.mode);
          break;
        case "stage-changed":
          setCurrentStage(event.stage);
          break;
        case "approval-needed":
          setPendingApprovals((prev) => [...prev, event.approval]);
          break;
        case "approval-resolved":
          setPendingApprovals((prev) => prev.filter((a) => a.id !== event.id));
          break;
        case "action-completed":
          setActionHistory((prev) => [...prev, event.entry]);
          if (event.entry.decision === "approved" || event.entry.decision === "auto-approved") {
            setApprovedCount((c) => c + 1);
          } else if (event.entry.decision === "denied") {
            setDeniedCount((c) => c + 1);
          }
          break;
        case "attack-surface-updated":
          sidebar.updateState({
            attackSurface: [
              ...sidebar.state.attackSurface,
              ...(event.endpoints || []).filter(
                (e: Endpoint) =>
                  !sidebar.state.attackSurface.some(
                    (existing) => `${existing.method}:${existing.path}` === `${e.method}:${e.path}`
                  )
              ),
            ],
          });
          break;
        case "finding-verified":
          sidebar.updateState({
            verifiedVulns: [...sidebar.state.verifiedVulns, event.finding],
          });
          break;
        case "target-state-updated":
          if (event.state?.ports) {
            const existingPorts = new Set(sidebar.state.ports.map((p) => p.port));
            const newPorts = event.state.ports.filter((p: any) => !existingPorts.has(p.port));
            if (newPorts.length > 0) {
              sidebar.updateState({
                ports: [...sidebar.state.ports, ...newPorts],
              });
            }
          }
          break;
        case "credential-found":
          if (!sidebar.state.credentials.some((c) => c.id === event.credential.id)) {
            sidebar.updateState({
              credentials: [...sidebar.state.credentials, event.credential],
            });
          }
          break;
        case "endpoint-status-changed":
          sidebar.updateState({
            attackSurface: sidebar.state.attackSurface.map((ep) =>
              ep.id === event.endpointId
                ? { ...ep, status: event.status, vulnType: event.vulnType }
                : ep
            ),
          });
          break;
      }
    });

    // Token usage
    operatorAgent.on("token-usage", ({ inputTokens, outputTokens }: { inputTokens: number; outputTokens: number }) => {
      addTokenUsage(inputTokens, outputTokens);
    });

    setAgent(operatorAgent);

    return () => {
      operatorAgent.stop();
    };
    // Note: We intentionally exclude messages.length from dependencies
    // The agent should only be created once, not re-created on message changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, model.id, isResume, resumeLoaded]);

  // ============================================
  // Send Initial Directive
  // ============================================

  const [initialDirectiveSent, setInitialDirectiveSent] = useState(false);

  useEffect(() => {
    if (!agent || !initialDirective || initialDirectiveSent) return;

    // Send the initial directive
    setInitialDirectiveSent(true);
    agent.sendDirective(initialDirective);
  }, [agent, initialDirective, initialDirectiveSent]);

  // ============================================
  // Event Handlers
  // ============================================

  const handleModeChange = useCallback((newMode: OperatorMode) => {
    agent?.setMode(newMode);
    setOperatorMode(newMode);
  }, [agent]);

  const cycleMode = useCallback((reverse: boolean = false) => {
    const modes: OperatorMode[] = ["plan", "manual", "auto"];
    const currentIdx = modes.indexOf(operatorMode);
    const nextIdx = reverse
      ? (currentIdx - 1 + modes.length) % modes.length
      : (currentIdx + 1) % modes.length;
    handleModeChange(modes[nextIdx]);
  }, [operatorMode, handleModeChange]);

  const handleStageChange = useCallback((newStage: OperatorStage) => {
    agent?.setStage(newStage);
    setCurrentStage(newStage);
    setShowStageMenu(false);
  }, [agent]);

  const handleApprove = useCallback((approvalId: string) => {
    const approval = pendingApprovals.find((a) => a.id === approvalId);
    if (approval) {
      const args = approval.args || {};
      let actionDesc = approval.toolName;
      if (approval.toolName === "http_request" && args.method && args.url) {
        actionDesc = `${args.method} ${args.url}`;
      } else if (approval.toolName === "execute_command" && args.command) {
        actionDesc = `$ ${String(args.command).slice(0, 50)}`;
      }
      setLastApprovedAction(actionDesc);
    }
    setLastDeclineNote(null);
    agent?.approve(approvalId);
  }, [agent, pendingApprovals]);

  const handleDeny = useCallback((approvalId: string) => {
    agent?.deny(approvalId);
  }, [agent]);

  const handleAutoApproveTier = useCallback((tier: PermissionTier) => {
    setOperatorMode("auto");
    agent?.setMode("auto");
    setAutoApproveTier(tier);
    agent?.setAutoApproveTier(tier);

    pendingApprovals.forEach((approval) => {
      if (approval.tier <= tier) {
        agent?.approve(approval.id);
      }
    });
  }, [agent, pendingApprovals]);

  const handleSendDirective = useCallback(async (directive: string) => {
    if (!directive.trim()) return;
    const trimmed = directive.trim();
    setDirectiveInput("");

    // Handle slash commands
    if (trimmed.startsWith("/")) {
      const parts = trimmed.slice(1).split(/\s+/);
      const cmd = parts[0]?.toLowerCase();
      const arg = parts[1];

      // /mode <plan|manual|auto>
      if (cmd === "mode") {
        const validModes: OperatorMode[] = ["plan", "manual", "auto"];
        if (arg && validModes.includes(arg as OperatorMode)) {
          handleModeChange(arg as OperatorMode);
          Session.updateOperatorSettings(session.id, { initialMode: arg as OperatorMode }).catch(() => {});
          addMessage({
            role: "system",
            content: `Mode changed to ${OPERATOR_MODES[arg as OperatorMode].name}`,
            createdAt: new Date(),
          });
        } else {
          addMessage({
            role: "system",
            content: `Current mode: ${OPERATOR_MODES[operatorMode].name}\nUsage: /mode <plan|manual|auto>`,
            createdAt: new Date(),
          });
        }
        return;
      }

      // /tier <1-5>
      if (cmd === "tier") {
        const tierNum = parseInt(arg || "", 10);
        if (tierNum >= 1 && tierNum <= 5) {
          const newTier = tierNum as PermissionTier;
          setAutoApproveTier(newTier);
          agent?.setAutoApproveTier(newTier);
          Session.updateOperatorSettings(session.id, { autoApproveTier: newTier }).catch(() => {});
          addMessage({
            role: "system",
            content: `Auto-approve tier set to T${newTier} (${PERMISSION_TIERS[newTier].name})`,
            createdAt: new Date(),
          });
        } else {
          addMessage({
            role: "system",
            content: `Current tier: T${autoApproveTier} (${PERMISSION_TIERS[autoApproveTier].name})\nUsage: /tier <1-5>`,
            createdAt: new Date(),
          });
        }
        return;
      }

      // /config
      if (cmd === "config") {
        const config = [
          `Session: ${session.name || session.id}`,
          `Target: ${session.targets[0]}`,
          `Mode: ${OPERATOR_MODES[operatorMode].name}`,
          `Auto-approve Tier: T${autoApproveTier}`,
          `Stage: ${OPERATOR_STAGES[currentStage].name}`,
          `Verbose: ${verboseMode ? "on" : "off"}`,
          "",
          `Commands: /mode <plan|manual|auto>, /tier <1-5>, /config, /tools`,
        ].join("\n");
        addMessage({
          role: "system",
          content: config,
          createdAt: new Date(),
        });
        return;
      }

      // /tools - Open tools panel
      if (cmd === "tools" || cmd === "t") {
        setShowToolsPanel(true);
        return;
      }
    }

    // Not a slash command - send as directive
    if (!agent) return;

    // If there's a pending approval, deny it and send as redirect
    if (pendingApprovals.length > 0) {
      const approval = pendingApprovals[0];
      try {
        agent.deny(approval.id);
      } catch {
        // Approval may have already been resolved - ignore
      }
      setLastDeclineNote(trimmed);
    } else {
      setLastDeclineNote(null);
    }

    await agent.sendDirective(trimmed);
  }, [
    agent, pendingApprovals, operatorMode, autoApproveTier, currentStage, session,
    handleModeChange, verboseMode, addMessage,
  ]);

  const handleExit = useCallback(() => {
    // Save state before exiting
    Session.saveOperatorState(session.id, gatherOperatorState()).catch(() => {});
    agent?.stop();
    if (onExit) {
      onExit();
    } else {
      route.navigate({ type: "base", path: "home" });
    }
  }, [session.id, gatherOperatorState, agent, onExit, route]);

  // ============================================
  // Keyboard Handling
  // ============================================

  useKeyboard((key) => {
    // Handle tools panel - let it handle its own keyboard events
    if (showToolsPanel) {
      // ESC is handled by the panel itself
      return;
    }

    // Handle stage menu
    if (showStageMenu) {
      if (key.name === "escape") {
        setShowStageMenu(false);
        return;
      }
      const stages = getStagesInOrder();
      const num = parseInt(key.name || "", 10);
      if (num >= 1 && num <= stages.length) {
        handleStageChange(stages[num - 1].stage);
        return;
      }
      return;
    }

    // Ctrl+T - Open tools panel
    if (key.ctrl && key.name === "t") {
      setShowToolsPanel(true);
      return;
    }

    const inputIsEmpty = directiveInput === "";

    // Handle pending approval shortcuts when input is empty
    if (inputIsEmpty && pendingApprovals.length > 0) {
      const approval = pendingApprovals[0];
      if (key.name === "y" || key.name === "Y") {
        handleApprove(approval.id);
        return;
      }
      if (key.name === "a" || key.name === "A") {
        handleAutoApproveTier(approval.tier);
        return;
      }
    }

    // Shift+Tab - Cycle modes (operator mode only)
    if (mode === "operator" && key.name === "tab" && key.shift) {
      cycleMode(false);
      return;
    }

    // Ctrl+B - Toggle sidebar
    if (key.ctrl && key.name === "b") {
      sidebar.toggleCollapsed();
      return;
    }

    // Ctrl+C - Clear input or stop agent
    if (key.ctrl && key.name === "c") {
      if (directiveInput.trim()) {
        setDirectiveInput("");
        return;
      }
      Session.saveOperatorState(session.id, gatherOperatorState()).catch(() => {});
      agent?.stop();
      return;
    }

    // ESC - Save and exit
    if (key.name === "escape") {
      handleExit();
      return;
    }

    // Ctrl+S - Stage menu (operator mode only)
    if (mode === "operator" && key.ctrl && key.name === "s") {
      setShowStageMenu(true);
      return;
    }

    // Option+T - Toggle verbose mode
    if (key.meta && key.name === "t") {
      setVerboseMode((v) => !v);
      return;
    }

    // Shift+O - Toggle expanded logs
    if (key.shift && (key.name === "o" || key.name === "O")) {
      setExpandedLogs((v) => !v);
      return;
    }

    // Enter to send directive
    if (key.name === "return" && directiveInput.trim()) {
      handleSendDirective(directiveInput);
      return;
    }
  });

  // ============================================
  // Computed Values
  // ============================================

  const chatStatus = useMemo(() => {
    if (status === "running") return "running" as const;
    if (pendingApprovals.length > 0) return "waiting" as const;
    if (status === "idle" && messages.length > 0) return "done" as const;
    return "idle" as const;
  }, [status, pendingApprovals, messages]);

  const stats = { approved: approvedCount, denied: deniedCount };

  // ============================================
  // Stage Menu Render
  // ============================================

  if (showStageMenu) {
    const stages = getStagesInOrder();
    return (
      <box flexDirection="column" width="100%" height="100%" padding={2}>
        <text fg={colors.creamText}>Select Stage:</text>
        <text fg={colors.dimText}> </text>
        {stages.map((s, idx) => (
          <text key={s.stage} fg={currentStage === s.stage ? colors.greenAccent : colors.dimText}>
            {"  "}[{idx + 1}] {s.name} - {s.description}
          </text>
        ))}
        <text fg={colors.dimText}> </text>
        <text fg={colors.dimText}>  [ESC] Cancel</text>
      </box>
    );
  }

  // ============================================
  // Main Render
  // ============================================

  return (
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {/* Header */}
      <Header
        mode={mode}
        target={session.targets[0]}
        sessionName={session.name}
        modelName={model.name}
        tokenUsage={tokenUsage}
        operatorMode={operatorMode}
        currentStage={currentStage}
        autoApproveTier={autoApproveTier}
        stats={mode === "operator" ? stats : undefined}
        endpointsCount={sidebar.state.attackSurface.length}
        findingsCount={sidebar.state.verifiedVulns.length}
        toolCallsCount={messages.filter((m) => m.role === "tool").length}
      />

      {/* Main content area */}
      <box flexDirection="row" flexGrow={1} paddingTop={1}>
        {/* Chat area */}
        <box
          flexDirection="column"
          flexGrow={1}
          overflow="hidden"
          width={mode === "operator" && !sidebar.collapsed ? "70%" : "100%"}
        >
          <MessageList
            messages={messages}
            streamingMessageIndex={streamingMessageIndex}
            isRunning={status === "running"}
            variant={mode}
            focused={true}
            verbose={verboseMode}
            expandedLogs={expandedLogs}
            pendingApprovals={pendingApprovals}
            hasPendingTool={hasPendingTool}
            lastApprovedAction={lastApprovedAction}
          />

          {/* Input area */}
          <InputArea
            value={directiveInput}
            onChange={setDirectiveInput}
            onSubmit={handleSendDirective}
            placeholder="Enter directive..."
            focused={!showToolsPanel}
            status={chatStatus}
            mode={mode}
            operatorMode={operatorMode}
            verboseMode={verboseMode}
            expandedLogs={expandedLogs}
            pendingApproval={pendingApprovals[0]}
            onApprove={() => pendingApprovals[0] && handleApprove(pendingApprovals[0].id)}
            onAutoApprove={() => pendingApprovals[0] && handleAutoApproveTier(pendingApprovals[0].tier)}
            lastDeclineNote={lastDeclineNote}
          />
        </box>

        {/* Sidebar (visible in operator mode or when explicitly shown) */}
        {mode === "operator" && (
          <Sidebar
            collapsed={sidebar.collapsed}
            state={sidebar.state}
          />
        )}
      </box>

      {/* Tools Panel Overlay */}
      <ToolsPanel
        open={showToolsPanel}
        onClose={() => {
          setShowToolsPanel(false);
          // Refocus the input after closing
          refocusPrompt();
        }}
        session={session}
        onToolsetChange={(newState: ToolsetState) => {
          // Toolset state is persisted by the panel itself
          // Agent will pick up the new state on next tool call
          addMessage({
            role: "system",
            content: "Toolset updated. Changes will apply to future agent actions.",
            createdAt: new Date(),
          });
        }}
      />
    </box>
  );
}

export { SessionComponent as Session };
export default SessionComponent;

// Re-export sub-components for external use
export { Header } from "../components/chat/header";
export { MessageList } from "../components/chat/message-list";
export { InputArea } from "../components/chat/input-area";
export { Sidebar, useSidebarState, type SidebarState } from "../components/chat/sidebar";
export { InlineApprovalPrompt } from "../components/chat/approval-inline";
export { ToolMessage } from "../components/chat/tool-message";
export { LoadingIndicator, type LoadingState } from "../components/chat/loading-indicator";
