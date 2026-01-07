/**
 * Operator Dashboard
 *
 * Claude Code-like terminal chat experience for Operator pentesting.
 * Features streaming text, inline approval prompts, and a clean terminal feel.
 */

import { useState, useEffect, useCallback, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { Session } from "../../../core/session";
import { createOperatorAgent, type OperatorAgent } from "../../../core/agent/operatorAgent";
import type { OperatorMode, OperatorStage, PermissionTier, PendingApproval, ActionHistoryEntry } from "../../../core/operator";
import { OPERATOR_STAGES, getStagesInOrder, PERMISSION_TIERS } from "../../../core/operator";
import { useRoute } from "../../context/route";
import { useInput } from "../../context/input";
import { useAgent } from "../../agentProvider";
import type { DisplayMessage } from "../agent-display";
import { ChatMessage } from "./chat-message";
import { SpinnerDots } from "../sprites";
import { AttackSurfacePanel, CredentialsPanel, TargetStatePanel, VerifiedVulnsPanel } from "./sidebar";
import type { Endpoint, VerifiedVuln, Credential, Hypothesis, Evidence } from "./types";

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
    // Not a URL, might be IP:port format
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
    // Not a URL, return as-is (might be IP or hostname)
    return target.replace(/:(\d+)$/, "");
  }
}

const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);
const redText = RGBA.fromInts(244, 67, 54, 255);
const orangeText = RGBA.fromInts(255, 152, 0, 255);

function formatTokenCount(count: number): string {
  if (count >= 1000000) {
    return `${(count / 1000000).toFixed(1)}M`;
  } else if (count >= 1000) {
    return `${(count / 1000).toFixed(1)}K`;
  }
  return count.toString();
}

function getTierColor(tier: PermissionTier) {
  if (tier <= 2) return greenAccent;
  if (tier === 3) return yellowText;
  if (tier === 4) return orangeText;
  return redText;
}

interface OperatorDashboardProps {
  session: Session.SessionInfo;
  /** If true, restore saved state from disk instead of starting fresh */
  isResume?: boolean;
}

export default function OperatorDashboard({ session, isResume = false }: OperatorDashboardProps) {
  const route = useRoute();
  const { model, addTokenUsage, tokenUsage, hasExecuted } = useAgent();
  const { setInputValue } = useInput();

  // Get Operator settings from session config
  const operatorSettings = session.config?.operatorSettings || {
    initialMode: "manual" as OperatorMode,
    autoApproveTier: 2 as PermissionTier,
  };

  // Dashboard starts directly in running mode (config is done in wizard)

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
  // Pre-computed stats counters (avoids O(n) filter on every render)
  const [approvedCount, setApprovedCount] = useState(0);
  const [deniedCount, setDeniedCount] = useState(0);

  // UI state
  const [directiveInput, setDirectiveInput] = useState("");
  const [showStageMenu, setShowStageMenu] = useState(false);
  const [verboseMode, setVerboseMode] = useState(false);
  const [lastApprovedAction, setLastApprovedAction] = useState<string | null>(null);

  // Sync directive input with global input context (prevents global shortcuts like ? while typing)
  useEffect(() => {
    setInputValue(directiveInput);
  }, [directiveInput, setInputValue]);

  // Enhanced sidebar state
  const [attackSurface, setAttackSurface] = useState<Endpoint[]>([]);
  const [verifiedVulns, setVerifiedVulns] = useState<VerifiedVuln[]>([]);

  // Parse host and port from target URL
  const targetHost = parseHostFromTarget(session.targets[0] || "");
  const initialPort = parsePortFromTarget(session.targets[0] || "");
  const [discoveredPorts, setDiscoveredPorts] = useState<{ port: number; service?: string }[]>(
    initialPort ? [{ port: initialPort, service: "http" }] : []
  );
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [hypotheses, setHypotheses] = useState<Hypothesis[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [resumeLoaded, setResumeLoaded] = useState(false);

  // Memoize pending tool check to avoid duplicate slice operations in render
  const hasPendingTool = useMemo(() => {
    const recentMessages = messages.slice(-5);
    return recentMessages.some(
      m => m.role === "tool" && (m as any).status === "pending"
    );
  }, [messages]);

  // Function to gather current state for saving
  const gatherOperatorState = useCallback((): Session.OperatorSessionState => ({
    mode,
    autoApproveTier,
    currentStage,
    messages,
    attackSurface,
    credentials,
    verifiedVulns,
    targetState: { host: targetHost, ports: discoveredPorts }, // Simplified target state
    hypotheses,
    evidence,
    actionHistory,
    pausedAt: new Date().toISOString(),
    lastRunId: agent?.currentRunId || '',
  }), [
    mode, autoApproveTier, currentStage, messages, attackSurface,
    credentials, verifiedVulns, targetHost, discoveredPorts, hypotheses, evidence,
    actionHistory, agent
  ]);

  // Load state on resume
  useEffect(() => {
    if (!isResume || resumeLoaded) return;

    Session.loadOperatorState(session.id).then((savedState) => {
      if (savedState) {
        setMode(savedState.mode as OperatorMode);
        setAutoApproveTier(savedState.autoApproveTier as PermissionTier);
        setCurrentStage(savedState.currentStage as OperatorStage);
        // Deserialize messages with proper date conversion and status reconciliation
        const restoredMessages = (savedState.messages || []).map((msg: any) => ({
          ...msg,
          createdAt: msg.createdAt ? new Date(msg.createdAt) : new Date(),
          // Force pending tools to completed - they won't re-run on resume
          status: msg.role === "tool" && msg.status === "pending" ? "completed" : msg.status,
        }));
        setMessages(restoredMessages);
        setAttackSurface(savedState.attackSurface || []);
        setCredentials(savedState.credentials || []);
        setVerifiedVulns(savedState.verifiedVulns || []);
        // Restore discovered ports from saved state
        if (savedState.targetState?.ports) {
          setDiscoveredPorts(savedState.targetState.ports);
        }
        setHypotheses(savedState.hypotheses || []);
        setEvidence(savedState.evidence || []);
        setActionHistory(savedState.actionHistory || []);
        // Initialize counters from restored action history
        const history = savedState.actionHistory || [];
        setApprovedCount(history.filter((a: any) => a.decision === "approved" || a.decision === "auto-approved").length);
        setDeniedCount(history.filter((a: any) => a.decision === "denied").length);
      }
      setResumeLoaded(true);
    });
  }, [isResume, session.id, resumeLoaded]);

  // Initialize agent
  useEffect(() => {
    if (agent) return; // Already initialized
    // Wait for resume state to load before creating agent
    if (isResume && !resumeLoaded) return;

    const operatorAgent = createOperatorAgent({
      session,
      model: model.id,
      initialMode: mode,
      autoApproveTier,
      initialStage: currentStage,
      // DEEP COPY messages on resume to prevent shared reference mutation
      // Without this, agent.addMessage() mutates dashboard state directly
      previousMessages: isResume ? messages.map(m => ({ ...m })) : undefined,
      // Pass attack surface for resume context - agent needs to know discovered endpoints
      previousAttackSurface: isResume ? attackSurface.map(e => ({
        method: e.method,
        path: e.path,
        status: e.status,
        category: e.category,
      })) : undefined,
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
          // Clear lastApprovedAction when agent starts responding
          setLastApprovedAction(null);
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
          // Increment pre-computed counters (avoids O(n) filter on every render)
          if (event.entry.decision === "approved" || event.entry.decision === "auto-approved") {
            setApprovedCount((c) => c + 1);
          } else if (event.entry.decision === "denied") {
            setDeniedCount((c) => c + 1);
          }
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

        // Port discovery - add newly discovered ports
        case "target-state-updated":
          if (event.state?.ports) {
            setDiscoveredPorts((prev) => {
              const existingPorts = new Set(prev.map(p => p.port));
              const newPorts = event.state.ports.filter((p: any) => !existingPorts.has(p.port));
              return newPorts.length > 0 ? [...prev, ...newPorts] : prev;
            });
          }
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

    operatorAgent.on("token-usage", ({ inputTokens, outputTokens }: { inputTokens: number; outputTokens: number }) => {
      addTokenUsage(inputTokens, outputTokens);
    });

    setAgent(operatorAgent);

    return () => {
      operatorAgent.stop();
    };
  }, [session, model.id, isResume, resumeLoaded]);

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
    // Find the approval to get action details for display
    const approval = pendingApprovals.find(a => a.id === approvalId);
    if (approval) {
      // Format the action for display (e.g., "smart_enumerate", "http_request GET /api")
      const args = approval.args || {};
      let actionDesc = approval.toolName;
      if (approval.toolName === "http_request" && args.method && args.url) {
        actionDesc = `${args.method} ${args.url}`;
      } else if (approval.toolName === "execute_command" && args.command) {
        actionDesc = `$ ${String(args.command).slice(0, 50)}`;
      }
      setLastApprovedAction(actionDesc);
    }
    agent?.approve(approvalId);
  }, [agent, pendingApprovals]);

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

    // IMPORTANT: Only intercept shortcuts when input is COMPLETELY empty
    // This prevents shortcuts from triggering while user is typing
    const inputIsEmpty = directiveInput === "";

    // Handle pending approval - intercept Y/N/A keys ONLY when input is empty
    if (inputIsEmpty && pendingApprovals.length > 0) {
      const approval = pendingApprovals[0];
      if (key.name === "y" || key.name === "Y") {
        handleApprove(approval.id);
        return;
      }
      if (key.name === "n" || key.name === "N") {
        handleDenyWithAlternatives(approval.id);
        return;
      }
      if (key.name === "a" || key.name === "A") {
        handleAutoApproveTier(approval.tier);
        return;
      }
    }

    // Shift+Tab - Cycle modes (plan → manual → auto)
    if (key.name === "tab" && key.shift) {
      cycleMode(false);
      return;
    }

    // Ctrl+C - Clear input first, then save state and stop agent if input is empty
    if (key.ctrl && key.name === "c") {
      if (directiveInput.trim()) {
        setDirectiveInput("");
        return;
      }
      // Save state before stopping
      Session.saveOperatorState(session.id, gatherOperatorState()).catch(() => {});
      agent?.stop();
      return;
    }

    // ESC - Save state, stop agent and exit to home
    if (key.name === "escape") {
      // Save state before exiting
      Session.saveOperatorState(session.id, gatherOperatorState()).catch(() => {});
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

  // Use pre-computed counters (O(1) instead of O(n) filter on every render)
  const stats = {
    approved: approvedCount,
    denied: deniedCount,
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
          {hasExecuted && (
            <text fg={creamText}>
              {`${formatTokenCount(tokenUsage.inputTokens)}/${formatTokenCount(tokenUsage.outputTokens)}`}
            </text>
          )}
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

            {/* Streaming indicator - show when agent is processing (thinking or executing) */}
            {status === "running" &&
              messages.length > 0 &&
              pendingApprovals.length === 0 &&
              messages[messages.length - 1]?.role !== "assistant" && (
              <box marginTop={1} marginLeft={2}>
                <SpinnerDots
                  label={
                    hasPendingTool
                      ? (lastApprovedAction ? `Executing: ${lastApprovedAction}` : "Executing...")
                      : "Thinking..."
                  }
                  fg="green"
                />
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
            {/* Shortcuts row */}
            <box flexDirection="row" gap={2} marginTop={1} backgroundColor="transparent">
              {mode === "plan" && <text fg={yellowText}>{"⏸  PLAN"}</text>}
              {mode === "auto" && <text fg={greenAccent}>{"▶▶ AUTO"}</text>}
              <text fg={verboseMode ? greenAccent : dimText}>
                {verboseMode ? "⌥T verbose:on" : "⌥T verbose"}
              </text>
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
          {/* Target - host and discovered ports */}
          <TargetStatePanel host={targetHost} ports={discoveredPorts} />

          {/* Attack Surface with status markers */}
          <AttackSurfacePanel endpoints={attackSurface} maxVisible={4} />

          {/* Credentials - discovered creds with source/scope */}
          <CredentialsPanel credentials={credentials} maxVisible={3} />

          {/* Verified Vulnerabilities */}
          <VerifiedVulnsPanel vulns={verifiedVulns} maxVisible={3} />
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
