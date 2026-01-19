/**
 * Chat View
 *
 * Main chat interface with message display, tool call rendering,
 * approval prompts, and status bar.
 */

import { useState, useEffect, useCallback, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { Session } from "../../../core/session";
import { createOperatorAgent, type OperatorAgent } from "../../../core/agent/operatorAgent";
import type { OperatorMode, OperatorStage, PermissionTier, PendingApproval } from "../../../core/operator";
import type { DisplayMessage } from "../agent-display";
import type { ModelInfo } from "../../../core/ai";
import { colors } from "../../theme";
import { isToolMessage, InlineApprovalPrompt, ApprovalInputArea } from "../shared";
import { MessageList } from "./components/message-list";
import { StatusBar, type ChatStatus } from "./components/status-bar";
import { ChatInputArea } from "./components/chat-input-area";
import type { Endpoint, VerifiedVuln, Credential } from "../operator-dashboard/types";

interface SidebarStateType {
  attackSurface: Endpoint[];
  credentials: Credential[];
  verifiedVulns: VerifiedVuln[];
  targetHost: string;
  ports: { port: number; service?: string }[];
}

interface ChatViewProps {
  session: Session.SessionInfo;
  model: ModelInfo;
  isResume?: boolean;
  onExit: () => void;
  /** Sidebar state (passed from parent) */
  sidebarState?: SidebarStateType;
  onSidebarUpdate?: (state: Partial<SidebarStateType>) => void;
}

export function ChatView({
  session,
  model,
  isResume = false,
  onExit,
  sidebarState,
  onSidebarUpdate,
}: ChatViewProps) {
  // Agent state
  const [agent, setAgent] = useState<OperatorAgent | null>(null);
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const [status, setStatus] = useState<string>("idle");
  const [streamingMessageIndex, setStreamingMessageIndex] = useState<number>(-1);

  // Operator state
  const [mode, setMode] = useState<OperatorMode>("manual");
  const [autoApproveTier, setAutoApproveTier] = useState<PermissionTier>(2);
  const [currentStage, setCurrentStage] = useState<OperatorStage>("setup");
  const [pendingApprovals, setPendingApprovals] = useState<PendingApproval[]>([]);

  // Token tracking
  const [tokenUsage, setTokenUsage] = useState({ input: 0, output: 0 });

  // UI state
  const [directiveInput, setDirectiveInput] = useState("");
  const [lastApprovedAction, setLastApprovedAction] = useState<string | null>(null);
  const [lastDeclineNote, setLastDeclineNote] = useState<string | null>(null);
  const [resumeLoaded, setResumeLoaded] = useState(false);

  // Memoize pending tool check
  const hasPendingTool = useMemo(() => {
    const recentMessages = messages.slice(-5);
    return recentMessages.some(
      (m) => isToolMessage(m) && m.status === "pending"
    );
  }, [messages]);

  // Map internal status to ChatStatus type
  const chatStatus: ChatStatus = useMemo(() => {
    if (status === "running") return "running";
    if (pendingApprovals.length > 0) return "waiting";
    if (status === "idle" && messages.length > 0) return "done";
    return "idle";
  }, [status, pendingApprovals, messages]);

  // Load state on resume
  useEffect(() => {
    if (!isResume || resumeLoaded) return;

    Session.loadOperatorState(session.id).then((savedState) => {
      if (savedState) {
        setMode(savedState.mode as OperatorMode);
        setAutoApproveTier(savedState.autoApproveTier as PermissionTier);
        setCurrentStage(savedState.currentStage as OperatorStage);

        // Deserialize messages
        const restoredMessages = (savedState.messages || []).map((msg: any) => ({
          ...msg,
          createdAt: msg.createdAt ? new Date(msg.createdAt) : new Date(),
          status: msg.role === "tool" && msg.status === "pending" ? "completed" : msg.status,
        }));
        setMessages(restoredMessages);

        // Update sidebar state if handler provided
        if (onSidebarUpdate) {
          onSidebarUpdate({
            attackSurface: savedState.attackSurface || [],
            credentials: savedState.credentials || [],
            verifiedVulns: savedState.verifiedVulns || [],
            ports: savedState.targetState?.ports || [],
          });
        }
      }
      setResumeLoaded(true);
    });
  }, [isResume, session.id, resumeLoaded, onSidebarUpdate]);

  // Initialize agent
  useEffect(() => {
    if (agent) return;
    if (isResume && !resumeLoaded) return;

    const operatorAgent = createOperatorAgent({
      session,
      model: model.id,
      initialMode: mode,
      autoApproveTier,
      initialStage: currentStage,
      previousMessages: isResume ? messages.map((m) => ({ ...m })) : undefined,
      previousAttackSurface: isResume && sidebarState?.attackSurface
        ? sidebarState.attackSurface.map((e) => ({
            method: e.method,
            path: e.path,
            status: e.status,
            category: e.category,
          }))
        : undefined,
    });

    // Set up event listeners
    operatorAgent.on("status-change", (newStatus: string) => {
      setStatus(newStatus);
    });

    operatorAgent.on("message", (message: DisplayMessage) => {
      setMessages((prev) => {
        const newMessages = [...prev, message];
        if (message.role === "assistant") {
          setStreamingMessageIndex(newMessages.length - 1);
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
        case "attack-surface-updated":
          if (onSidebarUpdate) {
            onSidebarUpdate({
              attackSurface: event.endpoints || [],
            });
          }
          break;
        case "finding-verified":
          if (onSidebarUpdate && event.finding) {
            onSidebarUpdate({
              verifiedVulns: [...(sidebarState?.verifiedVulns || []), event.finding],
            });
          }
          break;
        case "credential-found":
          if (onSidebarUpdate && event.credential) {
            const existing = sidebarState?.credentials || [];
            if (!existing.some((c) => c.id === event.credential.id)) {
              onSidebarUpdate({
                credentials: [...existing, event.credential],
              });
            }
          }
          break;
        case "target-state-updated":
          if (onSidebarUpdate && event.state?.ports) {
            onSidebarUpdate({
              ports: event.state.ports,
            });
          }
          break;
      }
    });

    operatorAgent.on("token-usage", ({ inputTokens, outputTokens }: { inputTokens: number; outputTokens: number }) => {
      setTokenUsage((prev) => ({
        input: prev.input + inputTokens,
        output: prev.output + outputTokens,
      }));
    });

    setAgent(operatorAgent);

    return () => {
      operatorAgent.stop();
    };
  }, [session, model.id, isResume, resumeLoaded]);

  // Handle approval
  const handleApprove = useCallback(
    (approvalId: string) => {
      const approval = pendingApprovals.find((a) => a.id === approvalId);
      if (approval) {
        const args = approval.args || {};
        let actionDesc = approval.toolName;
        if (approval.toolName === "http_request" && args.method && args.url) {
          actionDesc = `${args.method} ${args.url}`;
        }
        setLastApprovedAction(actionDesc);
      }
      setLastDeclineNote(null);
      agent?.approve(approvalId);
    },
    [agent, pendingApprovals]
  );

  // Handle auto-approve
  const handleAutoApproveTier = useCallback(
    (tier: PermissionTier) => {
      setMode("auto");
      agent?.setMode("auto");
      setAutoApproveTier(tier);
      agent?.setAutoApproveTier(tier);

      pendingApprovals.forEach((approval) => {
        if (approval.tier <= tier) {
          agent?.approve(approval.id);
        }
      });
    },
    [agent, pendingApprovals]
  );

  // Handle send directive
  const handleSendDirective = useCallback(
    async (directive: string) => {
      if (!agent || !directive.trim()) return;
      setDirectiveInput("");

      if (pendingApprovals.length > 0) {
        const approval = pendingApprovals[0];
        agent.deny(approval.id);
        setLastDeclineNote(directive.trim());
      } else {
        setLastDeclineNote(null);
      }

      await agent.sendDirective(directive);
    },
    [agent, pendingApprovals]
  );

  // Gather state for saving
  const gatherState = useCallback(() => ({
    mode,
    autoApproveTier,
    currentStage,
    messages,
    attackSurface: sidebarState?.attackSurface || [],
    credentials: sidebarState?.credentials || [],
    verifiedVulns: sidebarState?.verifiedVulns || [],
    targetState: {
      host: sidebarState?.targetHost || "",
      ports: sidebarState?.ports || [],
    },
    hypotheses: [],
    evidence: [],
    actionHistory: [],
    pausedAt: new Date().toISOString(),
    lastRunId: agent?.currentRunId || "",
  }), [mode, autoApproveTier, currentStage, messages, sidebarState, agent]);

  // Keyboard handling
  useKeyboard((key) => {
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

    // Ctrl+C - Clear input or stop agent
    if (key.ctrl && key.name === "c") {
      if (directiveInput.trim()) {
        setDirectiveInput("");
        return;
      }
      Session.saveOperatorState(session.id, gatherState()).catch(() => {});
      agent?.stop();
      return;
    }

    // ESC - Save and exit
    if (key.name === "escape") {
      Session.saveOperatorState(session.id, gatherState()).catch(() => {});
      agent?.stop();
      onExit();
      return;
    }

    // Enter to send directive
    if (key.name === "return" && directiveInput.trim()) {
      handleSendDirective(directiveInput);
      return;
    }
  });

  const hasPendingApproval = pendingApprovals.length > 0;
  const lastMessage = messages[messages.length - 1];
  const isRunning = status === "running";

  return (
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {/* Chat messages */}
      <MessageList
        messages={messages}
        streamingMessageIndex={streamingMessageIndex}
        isRunning={isRunning}
        focused={true}
      />

      {/* Approval prompt in chat flow */}
      {hasPendingApproval && (
        <InlineApprovalPrompt approval={pendingApprovals[0]} />
      )}

      {/* Thinking/executing indicator */}
      {isRunning && !hasPendingApproval && (
        <box marginTop={1} marginLeft={4}>
          <text
            fg={colors.dimText}
            content={
              hasPendingTool
                ? lastApprovedAction
                  ? `Executing: ${lastApprovedAction}`
                  : "Executing..."
                : "Thinking..."
            }
          />
        </box>
      )}

      {/* Cancel hint when running */}
      {isRunning && (
        <box marginTop={1} marginLeft={4}>
          <text fg={colors.dimText}>ctrl+c to cancel</text>
        </box>
      )}

      {/* Input area */}
      {hasPendingApproval ? (
        <ApprovalInputArea
          approval={pendingApprovals[0]}
          onApprove={() => handleApprove(pendingApprovals[0].id)}
          onAutoApprove={() => handleAutoApproveTier(pendingApprovals[0].tier)}
          onRedirect={handleSendDirective}
          redirectInput={directiveInput}
          setRedirectInput={setDirectiveInput}
          lastDeclineNote={lastDeclineNote}
        />
      ) : (
        <ChatInputArea
          value={directiveInput}
          onChange={setDirectiveInput}
          onSubmit={handleSendDirective}
          placeholder="Enter directive..."
          focused={true}
          status={chatStatus}
        />
      )}

      {/* Status bar */}
      <StatusBar
        status={chatStatus}
        modelName={model.name}
        tokenCount={tokenUsage}
      />
    </box>
  );
}

export default ChatView;
