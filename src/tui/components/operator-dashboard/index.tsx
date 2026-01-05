/**
 * Operator Dashboard
 *
 * Claude Code-like terminal chat experience for Operator pentesting.
 * Features streaming text, inline approval prompts, and a clean terminal feel.
 */

import { useState, useEffect, useCallback } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { Session } from "../../../core/session";
import { createOperatorAgent, type OperatorAgent } from "../../../core/agent/operatorAgent";
import type { OperatorMode, OperatorStage, PermissionTier, PendingApproval, ActionHistoryEntry } from "../../../core/operator";
import { OPERATOR_STAGES, getStagesInOrder, PERMISSION_TIERS } from "../../../core/operator";
import { useRoute } from "../../context/route";
import { useAgent } from "../../agentProvider";
import type { DisplayMessage } from "../agent-display";
import { ChatMessage } from "./chat-message";
import { SpinnerDots } from "../sprites";
import { AttackSurfacePanel, CredentialsPanel, SuggestionsPanel, TargetStatePanel, VerifiedVulnsPanel } from "./sidebar";
import type { Endpoint, Suggestion, VerifiedVuln, TargetState, Credential, Hypothesis, Evidence } from "./types";
import { parseSuggestionsFromText, createInitialTargetState } from "./types";

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

function getModeColor(mode: OperatorMode) {
  if (mode === "plan") return yellowText;
  if (mode === "auto") return greenAccent;
  return blueText;
}

interface OperatorDashboardProps {
  session: Session.SessionInfo;
}

export default function OperatorDashboard({ session }: OperatorDashboardProps) {
  const route = useRoute();
  const { model } = useAgent();

  // Get Operator settings from session config
  const operatorSettings = session.config?.operatorSettings || {
    initialMode: "manual" as OperatorMode,
    autoApproveTier: 2 as PermissionTier,
  };

  // Agent state
  const [agent, setAgent] = useState<OperatorAgent | null>(null);
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const [status, setStatus] = useState<string>("idle");
  const [streamingMessageIndex, setStreamingMessageIndex] = useState<number>(-1);

  // Operator state
  const [mode, setMode] = useState<OperatorMode>(operatorSettings.initialMode);
  const [autoApproveTier, setAutoApproveTier] = useState<PermissionTier>(operatorSettings.autoApproveTier as PermissionTier);
  const [currentStage, setCurrentStage] = useState<OperatorStage>("setup");
  const [pendingApprovals, setPendingApprovals] = useState<PendingApproval[]>([]);
  const [actionHistory, setActionHistory] = useState<ActionHistoryEntry[]>([]);

  // UI state
  const [directiveInput, setDirectiveInput] = useState("");
  const [showStageMenu, setShowStageMenu] = useState(false);
  const [verboseMode, setVerboseMode] = useState(false);

  // Enhanced sidebar state
  const [attackSurface, setAttackSurface] = useState<Endpoint[]>([]);
  const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
  const [verifiedVulns, setVerifiedVulns] = useState<VerifiedVuln[]>([]);

  // Tier 1 panel state
  const [targetState, setTargetState] = useState<TargetState | null>(
    session.targets[0] ? createInitialTargetState(session.targets[0]) : null
  );
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [hypotheses, setHypotheses] = useState<Hypothesis[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);

  // Parse suggestions from latest assistant message
  useEffect(() => {
    if (messages.length === 0) return;
    const lastMessage = messages[messages.length - 1];
    if (lastMessage.role !== "assistant") return;

    // Get text content from message (content can be string or array)
    let textContent = "";
    if (typeof lastMessage.content === "string") {
      textContent = lastMessage.content;
    } else if (Array.isArray(lastMessage.content)) {
      textContent = lastMessage.content
        .filter((c: any) => c?.type === "text" && typeof c?.text === "string")
        .map((c: any) => c.text)
        .join("\n");
    }

    const parsed = parseSuggestionsFromText(textContent);
    if (parsed.length > 0) {
      setSuggestions(parsed);
    }
  }, [messages]);

  // Initialize agent
  useEffect(() => {
    const operatorAgent = createOperatorAgent({
      session,
      model: model.id,
      initialMode: mode,
      autoApproveTier,
      initialStage: "setup",
    });

    // Set up event listeners
    operatorAgent.on("status-change", (newStatus: string) => {
      setStatus(newStatus);
    });

    operatorAgent.on("message", (message: DisplayMessage) => {
      setMessages((prev) => {
        const newMessages = [...prev, message];
        // Track streaming assistant message
        if (message.role === "assistant") {
          setStreamingMessageIndex(newMessages.length - 1);
        }
        return newMessages;
      });
    });

    operatorAgent.on("message-updated", ({ index, message }: { index: number; message: DisplayMessage }) => {
      setMessages((prev) => {
        const newMessages = [...prev];
        newMessages[index] = message;
        return newMessages;
      });
    });

    operatorAgent.on("operator-event", (event: any) => {
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
        case "attack-surface-updated":
          // Merge new endpoints with existing, avoiding duplicates
          setAttackSurface((prev) => {
            const existing = new Set(prev.map(e => `${e.method}:${e.path}`));
            const newEndpoints = (event.endpoints || []).filter(
              (e: Endpoint) => !existing.has(`${e.method}:${e.path}`)
            );
            return [...prev, ...newEndpoints];
          });
          break;
        case "finding-verified":
          // Add new verified vulnerability
          setVerifiedVulns((prev) => [...prev, event.finding]);
          break;

        // Tier 1 events
        case "target-state-updated":
          // Update target state (host, ports, auth, focus)
          setTargetState((prev) => prev ? { ...prev, ...event.state } : event.state);
          break;
        case "phase-transition-suggested":
          // Set pending phase for Y/N confirmation
          setTargetState((prev) => prev ? { ...prev, pendingPhase: event.phase } : null);
          break;
        case "objective-proposed":
          // Update objective (unless user override exists)
          setTargetState((prev) => {
            if (!prev) return null;
            if (prev.objectiveOverride) return prev; // User override takes precedence
            return { ...prev, objective: event.objective };
          });
          break;
        case "credential-found":
          // Append new credential
          setCredentials((prev) => {
            // Avoid duplicates by checking id
            if (prev.some((c) => c.id === event.credential.id)) return prev;
            return [...prev, event.credential];
          });
          break;
        case "endpoint-status-changed":
          // Update endpoint status marker
          setAttackSurface((prev) =>
            prev.map((ep) =>
              ep.id === event.endpointId
                ? { ...ep, status: event.status, vulnType: event.vulnType }
                : ep
            )
          );
          break;
        case "hypothesis-recorded":
          // Append hypothesis for stuck detection
          setHypotheses((prev) => [...prev, event.hypothesis]);
          break;
        case "evidence-captured":
          // Append evidence with stable ID
          setEvidence((prev) => [...prev, event.evidence]);
          break;
      }
    });

    setAgent(operatorAgent);

    return () => {
      operatorAgent.stop();
    };
  }, [session, model.id]);

  // Handle mode change
  const handleModeChange = useCallback((newMode: OperatorMode) => {
    if (agent) {
      agent.setMode(newMode);
    }
    setMode(newMode);
  }, [agent]);

  // Cycle through modes with Tab/Shift+Tab
  const cycleMode = useCallback((reverse: boolean = false) => {
    const modes: OperatorMode[] = ["plan", "manual", "auto"];
    const currentIdx = modes.indexOf(mode);
    const nextIdx = reverse
      ? (currentIdx - 1 + modes.length) % modes.length
      : (currentIdx + 1) % modes.length;
    handleModeChange(modes[nextIdx]);
  }, [mode, handleModeChange]);

  // Handle stage change
  const handleStageChange = useCallback((newStage: OperatorStage) => {
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

  // Handle auto-approve tier upgrade - switches to auto mode and sets tier
  const handleAutoApproveTier = useCallback((tier: PermissionTier) => {
    // Switch to auto mode so the tier setting actually takes effect
    setMode("auto");
    agent?.setMode("auto");

    // Set the auto-approve tier
    setAutoApproveTier(tier);
    agent?.setAutoApproveTier(tier);

    // Auto-approve any pending approvals that are now within the tier
    pendingApprovals.forEach((approval) => {
      if (approval.tier <= tier) {
        agent?.approve(approval.id);
      }
    });
  }, [agent, pendingApprovals]);

  // Handle sending directive (can be used to redirect during approval)
  const handleSendDirective = useCallback(async (directive: string) => {
    if (!agent || !directive.trim()) return;
    setDirectiveInput("");

    // If there's a pending approval, deny it and send the directive as a redirect
    if (pendingApprovals.length > 0) {
      const approval = pendingApprovals[0];
      agent.deny(approval.id);
      // The directive will be sent after denial, acting as a redirect
    }

    await agent.sendDirective(directive);
  }, [agent, pendingApprovals]);

  // Handle denial with request for alternatives
  const handleDenyWithAlternatives = useCallback((approvalId: string) => {
    if (!agent) return;
    agent.deny(approvalId);
    // Send a message asking the agent to suggest alternatives
    agent.sendDirective("That action was denied. Please suggest 2-3 alternative approaches we could take instead, or ask me what I'd prefer to do.");
  }, [agent]);

  // Handle suggestion selection (1/2/3 keys)
  const handleSuggestionSelect = useCallback((num: number) => {
    const suggestion = suggestions.find((s) => s.number === num);
    if (!suggestion || !agent) return;

    // Clear suggestions after selection
    setSuggestions([]);

    // Send the suggestion label as a directive
    agent.sendDirective(suggestion.label);
  }, [agent, suggestions]);

  // Handle phase transition confirmation (Y/N)
  const handlePhaseConfirm = useCallback((confirmed: boolean) => {
    if (!targetState?.pendingPhase) return;

    if (confirmed) {
      // Accept the phase transition
      setTargetState((prev) => prev ? {
        ...prev,
        phase: prev.pendingPhase!,
        pendingPhase: undefined,
      } : null);
    } else {
      // Reject the phase transition
      setTargetState((prev) => prev ? {
        ...prev,
        pendingPhase: undefined,
      } : null);
    }
  }, [targetState]);

  // Keyboard handling
  useKeyboard((key) => {
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

    // Handle phase transition confirmation (Y/N when pendingPhase is set)
    if (targetState?.pendingPhase && !directiveInput.trim() && pendingApprovals.length === 0) {
      if (key.name === "y" || key.name === "Y") {
        setDirectiveInput("");
        handlePhaseConfirm(true);
        return;
      }
      if (key.name === "n" || key.name === "N") {
        setDirectiveInput("");
        handlePhaseConfirm(false);
        return;
      }
    }

    // Handle suggestion selection (1/2/3 keys) when input is empty and suggestions exist
    if (suggestions.length > 0 && !directiveInput.trim()) {
      const num = parseInt(key.name || "", 10);
      if (num >= 1 && num <= suggestions.length) {
        handleSuggestionSelect(num);
        return;
      }
    }

    // Handle pending approval - intercept Y/N/A keys
    // Check if input is empty OR just became a single Y/N/A character (key just typed)
    if (pendingApprovals.length > 0) {
      const approval = pendingApprovals[0];
      const inputIsEffectivelyEmpty = !directiveInput.trim() ||
        directiveInput.trim().toLowerCase() === key.name?.toLowerCase();

      if (inputIsEffectivelyEmpty) {
        if (key.name === "y" || key.name === "Y") {
          setDirectiveInput(""); // Clear any typed 'y'
          handleApprove(approval.id);
          return;
        }
        if (key.name === "n" || key.name === "N") {
          setDirectiveInput(""); // Clear any typed 'n'
          handleDenyWithAlternatives(approval.id);
          return;
        }
        if (key.name === "a" || key.name === "A") {
          setDirectiveInput(""); // Clear any typed 'a'
          handleAutoApproveTier(approval.tier);
          return;
        }
      }
    }

    // Shift+Tab - Cycle modes (plan → manual → auto)
    if (key.name === "tab" && key.shift) {
      cycleMode(false);
      return;
    }

    // Ctrl+C - Clear input first, then stop agent if input is empty
    if (key.ctrl && key.name === "c") {
      if (directiveInput.trim()) {
        setDirectiveInput("");
        return;
      }
      agent?.stop();
      return;
    }

    // ESC - Stop agent and exit to home
    if (key.name === "escape") {
      agent?.stop();
      route.navigate({ type: "base", path: "home" });
      return;
    }

    // Ctrl+S - Stage menu
    if (key.ctrl && key.name === "s") {
      setShowStageMenu(true);
      return;
    }

    // Option+T (meta+t) - Toggle verbose mode
    if (key.meta && key.name === "t") {
      setVerboseMode((v) => !v);
      return;
    }

    // Enter to send directive (works during approval or while agent is running)
    if (key.name === "return" && directiveInput.trim()) {
      handleSendDirective(directiveInput);
      return;
    }
  });

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
          {mode === "plan" && <text fg={yellowText}>{"⏸ "}</text>}
          {mode === "auto" && <text fg={greenAccent}>{"▶▶"}</text>}
          <text fg={dimText}>{OPERATOR_STAGES[currentStage].name}</text>
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
            focused={false}
          >
            {/* Welcome message if empty */}
            {messages.length === 0 && status === "idle" && (
              <box flexDirection="column" gap={1} marginTop={2}>
                <text fg={greenAccent}>Operator Mode Active</text>
                <text fg={dimText}>Type a directive to begin (e.g., "Explore the attack surface").</text>
                <text fg={dimText}>The agent will think out loud and suggest next steps inline.</text>
              </box>
            )}

            {/* Messages */}
            {messages.map((msg, idx) => (
              <ChatMessage
                key={`msg-${idx}-${msg.createdAt.getTime()}`}
                message={msg}
                isStreaming={status === "running" && idx === streamingMessageIndex}
                verbose={verboseMode}
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
                onAutoApprove={() => handleAutoApproveTier(pendingApprovals[0].tier)}
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
            backgroundColor="transparent"
          >
            <box flexDirection="row" gap={1} backgroundColor="transparent">
              <text fg={pendingApprovals.length > 0 ? dimText : greenAccent}>{">"}</text>
              <input
                width="100%"
                value={directiveInput}
                onInput={setDirectiveInput}
                onPaste={(event) => {
                  const cleaned = String(event.text).replace(/\r?\n/g, " ");
                  setDirectiveInput((prev) => prev + cleaned);
                }}
                focused={true}
                placeholder={pendingApprovals.length > 0 ? "Type to redirect, or Y/N/A..." : "Enter directive..."}
                textColor="white"
                backgroundColor="transparent"
              />
            </box>
            <box flexDirection="row" gap={2} marginTop={1} backgroundColor="transparent">
              {mode === "plan" && <text fg={yellowText}>{"⏸  PLAN"}</text>}
              {mode === "auto" && <text fg={greenAccent}>{"▶▶ AUTO"}</text>}
              <text fg={dimText}>^C {directiveInput.trim() ? "clear" : "stop"}</text>
              <text fg={dimText}>ESC quit</text>
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
          {/* Target State - externalizes agent's mental model */}
          <TargetStatePanel target={targetState} onPhaseConfirm={handlePhaseConfirm} />

          {/* Attack Surface with status markers */}
          <AttackSurfacePanel endpoints={attackSurface} maxVisible={4} />

          {/* Credentials - discovered creds with source/scope */}
          <CredentialsPanel credentials={credentials} maxVisible={3} />

          {/* Suggestions */}
          <SuggestionsPanel suggestions={suggestions} />

          {/* Verified Vulnerabilities */}
          <VerifiedVulnsPanel vulns={verifiedVulns} maxVisible={3} />

          {/* Stage indicator - compact */}
          <box flexDirection="column" gap={1}>
            <text fg={dimText}>
              Stage: <span fg={greenAccent}>{OPERATOR_STAGES[currentStage].name}</span>
            </text>
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
          <span fg={dimText}> No + suggest alt</span>
        </text>
        <text>
          <span fg={yellowText}>[A]</span>
          <span fg={dimText}> Auto T1-T{approval.tier}</span>
        </text>
      </box>
      <box marginLeft={3} marginTop={1}>
        <text fg={dimText}>Or type a message to redirect the agent...</text>
      </box>
    </box>
  );
}
