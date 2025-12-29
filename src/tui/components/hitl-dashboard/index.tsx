/**
 * HITL Dashboard
 *
 * Main dashboard for Human-in-the-Loop pentesting mode.
 * Provides approval gates, stage-aware workflow, and suggestions.
 */

import { useState, useEffect, useCallback, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { Session } from "../../../core/session";
import { createHITLAgent, type HITLAgent } from "../../../core/agent/hitlAgent";
import type { HITLMode, HITLStage, PermissionTier, PendingApproval, ActionHistoryEntry } from "../../../core/hitl";
import { HITL_MODES, HITL_STAGES, getStagesInOrder } from "../../../core/hitl";
import { getSuggestedActions } from "../../../core/agent/hitlAgent/suggestActions";
import { useRoute } from "../../context/route";
import { useAgent } from "../../agentProvider";
import AgentDisplay, { type DisplayMessage } from "../agent-display";
import ModeBanner from "./mode-banner";
import StageIndicator from "./stage-indicator";
import ApprovalPrompt from "./approval-prompt";
import SuggestedActions from "./suggested-actions";
import AuditLog from "./audit-log";

const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const darkBg = RGBA.fromInts(10, 10, 10, 255);

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

  // HITL state
  const [mode, setMode] = useState<HITLMode>(hitlSettings.initialMode);
  const [autoApproveTier, setAutoApproveTier] = useState<PermissionTier>(hitlSettings.autoApproveTier as PermissionTier);
  const [currentStage, setCurrentStage] = useState<HITLStage>("setup");
  const [pendingApprovals, setPendingApprovals] = useState<PendingApproval[]>([]);
  const [actionHistory, setActionHistory] = useState<ActionHistoryEntry[]>([]);

  // UI state
  const [showModeMenu, setShowModeMenu] = useState(false);
  const [showStageMenu, setShowStageMenu] = useState(false);
  const [directiveInput, setDirectiveInput] = useState("");
  const [focusedSuggestion, setFocusedSuggestion] = useState(-1);
  const [inputFocused, setInputFocused] = useState(false);

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
      setMessages((prev) => [...prev, message]);
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

  // Handle sending directive
  const handleSendDirective = useCallback(async (directive: string) => {
    if (!agent || !directive.trim()) return;
    setDirectiveInput("");
    setInputFocused(false);
    await agent.sendDirective(directive);
  }, [agent]);

  // Handle suggestion selection
  const handleSelectSuggestion = useCallback((directive: string) => {
    handleSendDirective(directive);
    setFocusedSuggestion(-1);
  }, [handleSendDirective]);

  // Get suggestions
  const suggestions = useMemo(() => {
    return getSuggestedActions(currentStage, actionHistory, { target: session.targets[0] });
  }, [currentStage, actionHistory, session.targets]);

  // Keyboard handling
  useKeyboard((key) => {
    // Handle menus first
    if (showModeMenu) {
      if (key.name === "escape") {
        setShowModeMenu(false);
        return;
      }
      const modes: HITLMode[] = ["plan", "manual", "auto"];
      if (key.name === "up" || key.name === "down") {
        const idx = modes.indexOf(mode);
        const newIdx = key.name === "up" ? (idx - 1 + modes.length) % modes.length : (idx + 1) % modes.length;
        handleModeChange(modes[newIdx]);
        return;
      }
      if (key.name === "return") {
        setShowModeMenu(false);
        return;
      }
      // Quick select by key
      if (key.name === "p") { handleModeChange("plan"); return; }
      if (key.name === "m") { handleModeChange("manual"); return; }
      if (key.name === "a") { handleModeChange("auto"); return; }
      return;
    }

    if (showStageMenu) {
      if (key.name === "escape") {
        setShowStageMenu(false);
        return;
      }
      const stages = getStagesInOrder();
      const currentIdx = stages.findIndex((s) => s.stage === currentStage);
      if (key.name === "up") {
        const newIdx = Math.max(0, currentIdx - 1);
        handleStageChange(stages[newIdx].stage);
        return;
      }
      if (key.name === "down") {
        const newIdx = Math.min(stages.length - 1, currentIdx + 1);
        handleStageChange(stages[newIdx].stage);
        return;
      }
      if (key.name === "return") {
        setShowStageMenu(false);
        return;
      }
      return;
    }

    // Handle pending approval
    if (pendingApprovals.length > 0 && !inputFocused) {
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
        // Auto-approve this tier
        setAutoApproveTier(approval.tier);
        agent?.setAutoApproveTier(approval.tier);
        handleApprove(approval.id);
        return;
      }
    }

    // Global shortcuts
    if (!inputFocused) {
      if (key.name === "escape") {
        route.navigate({ type: "base", path: "home" });
        return;
      }

      if (key.name === "m" || key.name === "M") {
        setShowModeMenu(true);
        return;
      }

      if (key.name === "s" || key.name === "S") {
        setShowStageMenu(true);
        return;
      }

      // Number keys for suggestions
      const numKey = parseInt(key.name || "", 10);
      if (numKey >= 1 && numKey <= 5 && suggestions[numKey - 1]) {
        handleSelectSuggestion(suggestions[numKey - 1].directive);
        return;
      }

      // Tab to focus input
      if (key.name === "tab") {
        setInputFocused(true);
        return;
      }
    }

    // Input handling
    if (inputFocused) {
      if (key.name === "escape") {
        setInputFocused(false);
        setDirectiveInput("");
        return;
      }
      if (key.name === "return" && directiveInput.trim()) {
        handleSendDirective(directiveInput);
        return;
      }
    }
  });

  // Render mode menu overlay
  if (showModeMenu) {
    return (
      <box flexDirection="column" width="100%" height="100%" alignItems="center" justifyContent="center">
        <box flexDirection="column" border borderColor={greenBullet} padding={2} backgroundColor={darkBg}>
          <text fg={creamText}>Select Mode</text>
          {(["plan", "manual", "auto"] as HITLMode[]).map((m) => {
            const isSelected = mode === m;
            const def = HITL_MODES[m];
            return (
              <text key={m} fg={isSelected ? greenBullet : dimText}>
                {isSelected ? "● " : "○ "}
                [{m[0].toUpperCase()}] {def.name} - {def.description}
              </text>
            );
          })}
          <text fg={dimText}>↑/↓ to select, Enter to confirm, ESC to cancel</text>
        </box>
      </box>
    );
  }

  // Render stage menu overlay
  if (showStageMenu) {
    const stages = getStagesInOrder();
    return (
      <box flexDirection="column" width="100%" height="100%" alignItems="center" justifyContent="center">
        <box flexDirection="column" border borderColor={greenBullet} padding={2} backgroundColor={darkBg}>
          <text fg={creamText}>Select Stage</text>
          {stages.map((s) => {
            const isSelected = currentStage === s.stage;
            return (
              <text key={s.stage} fg={isSelected ? greenBullet : dimText}>
                {isSelected ? "● " : "○ "}
                {s.name} - {s.description}
              </text>
            );
          })}
          <text fg={dimText}>↑/↓ to select, Enter to confirm, ESC to cancel</text>
        </box>
      </box>
    );
  }

  // Main dashboard layout
  return (
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {/* Header */}
      <box
        flexDirection="row"
        justifyContent="space-between"
        alignItems="center"
        paddingLeft={2}
        paddingRight={2}
        paddingTop={1}
        paddingBottom={1}
        border={["bottom"]}
        borderColor={dimText}
      >
        <box flexDirection="column">
          <ModeBanner mode={mode} autoApproveTier={autoApproveTier} />
          <text fg={dimText}>Target: {session.targets[0]}</text>
        </box>
        <StageIndicator currentStage={currentStage} compact />
      </box>

      {/* Main content */}
      <box flexDirection="row" flexGrow={1} gap={2} paddingLeft={2} paddingRight={2} paddingTop={1}>
        {/* Agent messages - left side (70%) */}
        <box flexDirection="column" flexGrow={2} width="70%">
          {/* Pending approval prompt */}
          {pendingApprovals.length > 0 && (
            <ApprovalPrompt
              approval={pendingApprovals[0]}
              onApprove={() => handleApprove(pendingApprovals[0].id)}
              onDeny={() => handleDeny(pendingApprovals[0].id)}
              focused={!inputFocused}
            />
          )}

          {/* Messages */}
          <box flexGrow={1}>
            <AgentDisplay
              messages={messages}
              isStreaming={status === "running"}
              focused={!inputFocused && pendingApprovals.length === 0}
            />
          </box>
        </box>

        {/* Sidebar - right side (30%) */}
        <box flexDirection="column" width="30%" gap={2}>
          <SuggestedActions
            currentStage={currentStage}
            actionHistory={actionHistory}
            target={session.targets[0]}
            focusedIndex={focusedSuggestion}
          />
          <AuditLog history={actionHistory} maxItems={8} />
        </box>
      </box>

      {/* Input bar */}
      <box
        flexDirection="column"
        paddingLeft={2}
        paddingRight={2}
        paddingTop={1}
        paddingBottom={1}
        border={["top"]}
        borderColor={dimText}
      >
        <box flexDirection="row" gap={1}>
          <text fg={inputFocused ? greenBullet : dimText}>{">"}</text>
          <input
            width="100%"
            value={directiveInput}
            onInput={setDirectiveInput}
            focused={inputFocused}
            placeholder="Enter directive... (Tab to focus)"
            textColor={inputFocused ? "white" : "gray"}
          />
        </box>
        <box flexDirection="row" gap={2}>
          <text fg={dimText}>[M] Mode</text>
          <text fg={dimText}>[S] Stage</text>
          <text fg={dimText}>[1-5] Suggestions</text>
          <text fg={dimText}>[Tab] Input</text>
          <text fg={dimText}>[ESC] Exit</text>
        </box>
      </box>
    </box>
  );
}
