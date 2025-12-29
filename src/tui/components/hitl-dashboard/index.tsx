/**
 * HITL Dashboard
 *
 * Claude Code-like terminal chat experience for Human-in-the-Loop pentesting.
 * Features streaming text, inline approval prompts, and a clean terminal feel.
 */

import { useState, useEffect, useCallback, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { Session } from "../../../core/session";
import { createHITLAgent, type HITLAgent } from "../../../core/agent/hitlAgent";
import type { HITLMode, HITLStage, PermissionTier, PendingApproval, ActionHistoryEntry } from "../../../core/hitl";
import { HITL_MODES, HITL_STAGES, getStagesInOrder, PERMISSION_TIERS } from "../../../core/hitl";
import { getSuggestedActions } from "../../../core/agent/hitlAgent/suggestActions";
import { useRoute } from "../../context/route";
import { useAgent } from "../../agentProvider";
import type { DisplayMessage } from "../agent-display";
import { ChatMessage } from "./chat-message";
import { SpinnerDots } from "../sprites";

const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);
const redText = RGBA.fromInts(244, 67, 54, 255);
const orangeText = RGBA.fromInts(255, 152, 0, 255);
const blueText = RGBA.fromInts(100, 181, 246, 255);

function getTierColor(tier: PermissionTier) {
  if (tier <= 2) return greenAccent;
  if (tier === 3) return yellowText;
  if (tier === 4) return orangeText;
  return redText;
}

function getModeColor(mode: HITLMode) {
  if (mode === "plan") return yellowText;
  if (mode === "auto") return greenAccent;
  return blueText;
}

interface HITLDashboardProps {
  session: Session.SessionInfo;
}

export default function HITLDashboard({ session }: HITLDashboardProps) {
  const route = useRoute();
  const { model } = useAgent();

  // Get HITL settings from session config
  const hitlSettings = session.config?.hitlSettings || {
    initialMode: "manual" as HITLMode,
    autoApproveTier: 2 as PermissionTier,
    enableSuggestions: true,
  };

  // Agent state
  const [agent, setAgent] = useState<HITLAgent | null>(null);
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const [status, setStatus] = useState<string>("idle");
  const [streamingMessageIndex, setStreamingMessageIndex] = useState<number>(-1);

  // HITL state
  const [mode, setMode] = useState<HITLMode>(hitlSettings.initialMode);
  const [autoApproveTier, setAutoApproveTier] = useState<PermissionTier>(hitlSettings.autoApproveTier as PermissionTier);
  const [currentStage, setCurrentStage] = useState<HITLStage>("setup");
  const [pendingApprovals, setPendingApprovals] = useState<PendingApproval[]>([]);
  const [actionHistory, setActionHistory] = useState<ActionHistoryEntry[]>([]);

  // UI state
  const [directiveInput, setDirectiveInput] = useState("");
  const [showModeMenu, setShowModeMenu] = useState(false);
  const [showStageMenu, setShowStageMenu] = useState(false);

  // Initialize agent
  useEffect(() => {
    const hitlAgent = createHITLAgent({
      session,
      model: model.id,
      initialMode: mode,
      autoApproveTier,
      initialStage: "setup",
    });

    // Set up event listeners
    hitlAgent.on("status-change", (newStatus: string) => {
      setStatus(newStatus);
    });

    hitlAgent.on("message", (message: DisplayMessage) => {
      setMessages((prev) => {
        const newMessages = [...prev, message];
        // Track streaming assistant message
        if (message.role === "assistant") {
          setStreamingMessageIndex(newMessages.length - 1);
        }
        return newMessages;
      });
    });

    hitlAgent.on("message-updated", ({ index, message }: { index: number; message: DisplayMessage }) => {
      setMessages((prev) => {
        const newMessages = [...prev];
        newMessages[index] = message;
        return newMessages;
      });
    });

    hitlAgent.on("hitl-event", (event: any) => {
      switch (event.type) {
        case "mode-changed":
          setMode(event.mode);
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
          break;
      }
    });

    setAgent(hitlAgent);

    return () => {
      hitlAgent.stop();
    };
  }, [session, model.id]);

  // Handle mode change
  const handleModeChange = useCallback((newMode: HITLMode) => {
    if (agent) {
      agent.setMode(newMode);
    }
    setMode(newMode);
    setShowModeMenu(false);
  }, [agent]);

  // Handle stage change
  const handleStageChange = useCallback((newStage: HITLStage) => {
    if (agent) {
      agent.setStage(newStage);
    }
    setCurrentStage(newStage);
    setShowStageMenu(false);
  }, [agent]);

  // Handle approval
  const handleApprove = useCallback((approvalId: string) => {
    agent?.approve(approvalId);
  }, [agent]);

  // Handle deny
  const handleDeny = useCallback((approvalId: string) => {
    agent?.deny(approvalId);
  }, [agent]);

  // Handle auto-approve tier upgrade
  const handleAutoApproveTier = useCallback((tier: PermissionTier) => {
    setAutoApproveTier(tier);
    agent?.setAutoApproveTier(tier);
  }, [agent]);

  // Handle sending directive
  const handleSendDirective = useCallback(async (directive: string) => {
    if (!agent || !directive.trim()) return;
    setDirectiveInput("");
    await agent.sendDirective(directive);
  }, [agent]);

  // Get suggestions
  const suggestions = useMemo(() => {
    return getSuggestedActions(currentStage, actionHistory, { target: session.targets[0] });
  }, [currentStage, actionHistory, session.targets]);

  // Keyboard handling
  useKeyboard((key) => {
    // Handle mode menu
    if (showModeMenu) {
      if (key.name === "escape") { setShowModeMenu(false); return; }
      if (key.name === "p") { handleModeChange("plan"); return; }
      if (key.name === "m") { handleModeChange("manual"); return; }
      if (key.name === "a") { handleModeChange("auto"); return; }
      return;
    }

    // Handle stage menu
    if (showStageMenu) {
      if (key.name === "escape") { setShowStageMenu(false); return; }
      const stages = getStagesInOrder();
      const num = parseInt(key.name || "", 10);
      if (num >= 1 && num <= stages.length) {
        handleStageChange(stages[num - 1].stage);
        return;
      }
      return;
    }

    // Handle pending approval
    if (pendingApprovals.length > 0) {
      const approval = pendingApprovals[0];
      if (key.name === "y" || key.name === "Y") {
        handleApprove(approval.id);
        return;
      }
      if (key.name === "n" || key.name === "N") {
        handleDeny(approval.id);
        return;
      }
      if (key.name === "a" || key.name === "A") {
        handleAutoApproveTier(approval.tier);
        handleApprove(approval.id);
        return;
      }
    }

    // ESC - Exit to home
    if (key.name === "escape") {
      route.navigate({ type: "base", path: "home" });
      return;
    }

    // Ctrl+M - Mode menu
    if (key.ctrl && key.name === "m") {
      setShowModeMenu(true);
      return;
    }

    // Ctrl+S - Stage menu
    if (key.ctrl && key.name === "s") {
      setShowStageMenu(true);
      return;
    }

    // Number keys for suggestions (only when not typing)
    if (!directiveInput) {
      const num = parseInt(key.name || "", 10);
      if (num >= 1 && num <= 5 && suggestions[num - 1]) {
        handleSendDirective(suggestions[num - 1].directive);
        return;
      }
    }

    // Enter to send directive
    if (key.name === "return" && directiveInput.trim()) {
      handleSendDirective(directiveInput);
      return;
    }
  });

  // Render mode menu overlay
  if (showModeMenu) {
    return (
      <box flexDirection="column" width="100%" height="100%" padding={2}>
        <text fg={creamText}>Select Mode:</text>
        <text fg={dimText}> </text>
        <text fg={mode === "plan" ? yellowText : dimText}>  [P] Plan - Read-only, propose actions</text>
        <text fg={mode === "manual" ? blueText : dimText}>  [M] Manual - Approve each action</text>
        <text fg={mode === "auto" ? greenAccent : dimText}>  [A] Auto - Auto-approve T1-T{autoApproveTier}</text>
        <text fg={dimText}> </text>
        <text fg={dimText}>  [ESC] Cancel</text>
      </box>
    );
  }

  // Render stage menu overlay
  if (showStageMenu) {
    const stages = getStagesInOrder();
    return (
      <box flexDirection="column" width="100%" height="100%" padding={2}>
        <text fg={creamText}>Select Stage:</text>
        <text fg={dimText}> </text>
        {stages.map((s, idx) => (
          <text key={s.stage} fg={currentStage === s.stage ? greenAccent : dimText}>
            {"  "}[{idx + 1}] {s.name} - {s.description}
          </text>
        ))}
        <text fg={dimText}> </text>
        <text fg={dimText}>  [ESC] Cancel</text>
      </box>
    );
  }

  // Compact stats
  const stats = {
    approved: actionHistory.filter((a) => a.decision === "approved" || a.decision === "auto-approved").length,
    denied: actionHistory.filter((a) => a.decision === "denied").length,
  };

  return (
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {/* Minimal header bar */}
      <box
        flexDirection="row"
        justifyContent="space-between"
        paddingLeft={2}
        paddingRight={2}
        paddingTop={1}
      >
        <box flexDirection="row" gap={2}>
          <text fg={getModeColor(mode)}>[{mode.toUpperCase()}]</text>
          <text fg={dimText}>Stage: {HITL_STAGES[currentStage].name}</text>
          <text fg={dimText}>|</text>
          <text fg={dimText}>{session.targets[0]}</text>
        </box>
        <box flexDirection="row" gap={2}>
          <text fg={greenAccent}>{stats.approved} approved</text>
          {stats.denied > 0 && <text fg={redText}>{stats.denied} denied</text>}
        </box>
      </box>

      {/* Main content area */}
      <box flexDirection="row" flexGrow={1} paddingTop={1}>
        {/* Chat area - left side */}
        <box flexDirection="column" flexGrow={1} width="70%">
          <scrollbox
            style={{
              rootOptions: { flexGrow: 1, width: "100%" },
              contentOptions: { paddingLeft: 2, paddingRight: 2, flexDirection: "column" },
            }}
            stickyScroll={true}
            stickyStart="bottom"
            focused={pendingApprovals.length === 0}
          >
            {/* Welcome message if empty */}
            {messages.length === 0 && status === "idle" && (
              <box flexDirection="column" gap={1} marginTop={2}>
                <text fg={greenAccent}>HITL Mode Active</text>
                <text fg={dimText}>Type a directive or select a suggestion to begin.</text>
                <text fg={dimText}>The agent will request approval for risky actions.</text>
              </box>
            )}

            {/* Messages */}
            {messages.map((msg, idx) => (
              <ChatMessage
                key={`msg-${idx}-${msg.createdAt.getTime()}`}
                message={msg}
                isStreaming={status === "running" && idx === streamingMessageIndex}
              />
            ))}

            {/* Streaming indicator */}
            {status === "running" && messages.length > 0 && messages[messages.length - 1]?.role !== "assistant" && (
              <box marginTop={1} marginLeft={2}>
                <SpinnerDots label="Thinking..." fg="green" />
              </box>
            )}

            {/* Inline approval prompt */}
            {pendingApprovals.length > 0 && (
              <InlineApprovalPrompt
                approval={pendingApprovals[0]}
                onApprove={() => handleApprove(pendingApprovals[0].id)}
                onDeny={() => handleDeny(pendingApprovals[0].id)}
                onAutoApprove={() => {
                  handleAutoApproveTier(pendingApprovals[0].tier);
                  handleApprove(pendingApprovals[0].id);
                }}
              />
            )}
          </scrollbox>

          {/* Input area */}
          <box
            flexDirection="column"
            paddingLeft={2}
            paddingRight={2}
            paddingTop={1}
            paddingBottom={1}
          >
            <box flexDirection="row" gap={1}>
              <text fg={pendingApprovals.length > 0 ? dimText : greenAccent}>❯</text>
              <input
                width="100%"
                value={directiveInput}
                onInput={setDirectiveInput}
                focused={pendingApprovals.length === 0}
                placeholder={pendingApprovals.length > 0 ? "Respond to approval first..." : "Enter directive..."}
                textColor={pendingApprovals.length > 0 ? "gray" : "white"}
              />
            </box>
            <box flexDirection="row" gap={2} marginTop={1}>
              <text fg={dimText}>^M Mode</text>
              <text fg={dimText}>^S Stage</text>
              <text fg={dimText}>[1-5] Suggestions</text>
              <text fg={dimText}>[ESC] Exit</text>
            </box>
          </box>
        </box>

        {/* Sidebar - right side */}
        <box
          flexDirection="column"
          width="30%"
          paddingLeft={2}
          paddingRight={2}
          gap={2}
          border={["left"]}
          borderColor={dimText}
        >
          {/* Suggestions */}
          <box flexDirection="column" gap={1}>
            <text fg={creamText}>Suggestions</text>
            {suggestions.slice(0, 5).map((s, idx) => (
              <text key={s.id} fg={dimText}>
                <span fg={greenAccent}>[{idx + 1}]</span> {s.label}
              </text>
            ))}
            {suggestions.length === 0 && (
              <text fg={dimText}>No suggestions available</text>
            )}
          </box>

          {/* Audit log */}
          <box flexDirection="column" gap={1} flexGrow={1}>
            <text fg={creamText}>Recent Actions</text>
            {actionHistory.slice(-8).reverse().map((entry) => {
              const icon = entry.decision === "approved" ? "✓" : entry.decision === "auto-approved" ? "⚡" : "✗";
              const color = entry.decision === "denied" ? redText : entry.decision === "auto-approved" ? yellowText : greenAccent;
              return (
                <text key={entry.id} fg={dimText}>
                  <span fg={color}>{icon}</span> T{entry.tier} {entry.toolName}
                </text>
              );
            })}
            {actionHistory.length === 0 && (
              <text fg={dimText}>No actions yet</text>
            )}
          </box>
        </box>
      </box>
    </box>
  );
}

/**
 * Inline approval prompt - minimal, terminal-style
 */
function InlineApprovalPrompt({
  approval,
  onApprove,
  onDeny,
  onAutoApprove,
}: {
  approval: PendingApproval;
  onApprove: () => void;
  onDeny: () => void;
  onAutoApprove: () => void;
}) {
  const tierColor = getTierColor(approval.tier);
  const tierDef = PERMISSION_TIERS[approval.tier];

  // Format args preview
  const argsPreview = Object.entries(approval.args)
    .slice(0, 2)
    .map(([k, v]) => {
      const val = typeof v === "string" ? v : JSON.stringify(v);
      return `${k}: ${val.length > 30 ? val.slice(0, 27) + "..." : val}`;
    })
    .join(", ");

  return (
    <box flexDirection="column" marginTop={2} marginBottom={1}>
      <box flexDirection="row" gap={2}>
        <text fg={yellowText}>?</text>
        <text fg={creamText}>Approve action?</text>
        <text fg={tierColor}>[T{approval.tier} {tierDef.shortName}]</text>
      </box>
      <box marginLeft={3} marginTop={1}>
        <text fg={dimText}>{approval.toolName}: {argsPreview}</text>
      </box>
      <box flexDirection="row" gap={3} marginLeft={3} marginTop={1}>
        <text>
          <span fg={greenAccent}>[Y]</span>
          <span fg={dimText}> Yes</span>
        </text>
        <text>
          <span fg={redText}>[N]</span>
          <span fg={dimText}> No</span>
        </text>
        <text>
          <span fg={yellowText}>[A]</span>
          <span fg={dimText}> Always T{approval.tier}</span>
        </text>
      </box>
    </box>
  );
}
