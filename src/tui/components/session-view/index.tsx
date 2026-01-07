import { useState, useEffect, useCallback } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { useRoute } from "../../context/route";
import { useAgent } from "../../agentProvider";
import SwarmDashboard, {
  type UIMessage,
  type Subagent,
} from "../swarm-dashboard";
import DriverDashboard from "../driver-dashboard";
import OperatorDashboard from "../operator-dashboard";
import { Session } from "../../../core/session";
import {
  loadSessionState,
  type UISubagent,
} from "../../../core/session/loader";
import {
  runStreamlinedPentest,
  type StreamlinedPentestProgress,
} from "../../../core/agent/thoroughPentestAgent/streamlined";
import type {
  SubAgentSpawnInfo,
  SubAgentStreamEvent,
} from "../../../core/agent/orchestrator/orchestrator";
import type { MetaVulnerabilityTestResult } from "../../../core/agent/metaTestingAgent";
import { existsSync } from "fs";
import { exec } from "child_process";
import { SpinnerDots } from "../sprites";

// Color palette
const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

// UIMessage helper for tool messages
type ToolUIMessage = UIMessage & {
  role: "tool";
  toolCallId: string;
  toolName: string;
};

interface SessionViewProps {
  sessionId: string;
  /** If true, load existing session state without starting a new pentest */
  isResume?: boolean;
}

export default function SessionView({
  sessionId,
  isResume = false,
}: SessionViewProps) {
  const route = useRoute();
  const { model, setThinking, isExecuting, addTokenUsage, setIsExecuting } =
    useAgent();

  // Session state
  const [session, setSession] = useState<Session.SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Execution state
  const [subagents, setSubagents] = useState<Subagent[]>([]);
  const [isCompleted, setIsCompleted] = useState(false);
  const [abortController, setAbortController] =
    useState<AbortController | null>(null);
  const [startTime, setStartTime] = useState<Date | null>(null);
  const [hasStarted, setHasStarted] = useState(false);

  // Load session on mount
  useEffect(() => {
    async function loadSession() {
      try {
        const loadedSession = await Session.get(sessionId);
        if (!loadedSession) {
          setError(`Session not found: ${sessionId}`);
          setLoading(false);
          return;
        }
        setSession(loadedSession);

        // If resuming, load existing state from disk
        if (isResume) {
          try {
            const state = await loadSessionState(loadedSession);

            // Convert UISubagent to Subagent (they're compatible)
            const loadedSubagents: Subagent[] = state.subagents.map((s) => ({
              id: s.id,
              name: s.name,
              type: s.type,
              target: s.target,
              messages: s.messages,
              createdAt: s.createdAt,
              status: s.status,
            }));

            setSubagents(loadedSubagents);
            setIsCompleted(state.hasReport);
            setStartTime(new Date(loadedSession.time.created));
            setHasStarted(true); // Mark as started so we don't trigger new pentest
          } catch (e) {
            console.error("Failed to load session state:", e);
            // Fall through to show empty state - user can still view session
          }
        }

        setLoading(false);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load session");
        setLoading(false);
      }
    }
    loadSession();
  }, [sessionId, isResume]);

  // Start pentest once session is loaded (only if not resuming)
  // Skip auto-start for operator/driver modes - they have their own start logic
  useEffect(() => {
    if (session && !hasStarted && !loading && !isResume) {
      const mode = session.config?.mode;
      if (mode === 'operator' || mode === 'driver') {
        return; // These modes wait for user to initiate
      }
      setHasStarted(true);
      startPentest(session);
    }
  }, [session, hasStarted, loading, isResume]);

  // Cleanup: abort on unmount (safety net)
  useEffect(() => {
    return () => {
      if (abortController) {
        abortController.abort();
      }
    };
  }, [abortController]);

  // Start the pentest
  const startPentest = useCallback(
    async (execSession: Session.SessionInfo) => {
      setIsExecuting(true);
      setThinking(true);
      setStartTime(new Date());

      const controller = new AbortController();
      setAbortController(controller);

      let currentDiscoveryText = "";

      try {
        // Add discovery subagent
        setSubagents([
          {
            id: "attack-surface-discovery",
            name: "Attack Surface Discovery",
            type: "attack-surface",
            target: execSession.targets[0],
            messages: [],
            status: "pending",
            createdAt: new Date(),
          },
        ]);

        // Run streamlined pentest
        const result = await runStreamlinedPentest({
          target: execSession.targets[0],
          model: model.id,
          session: execSession,
          sessionConfig: execSession.config,
          abortSignal: controller.signal,

          // Use onStepFinish for UI updates (like metavuln agent does)
          // This is more reliable than raw stream chunks which can be interrupted
          onDiscoveryStepFinish: (step) => {
            const stepTokens =
              (step.usage?.inputTokens ?? 0) + (step.usage?.outputTokens ?? 0);
            if (stepTokens > 0)
              addTokenUsage(
                step.usage.inputTokens ?? 0,
                step.usage.outputTokens ?? 0
              );

            // Update messages from step data (same pattern as onPentestAgentStream)
            const { text, toolCalls, toolResults } = step;

            setSubagents((prev) => {
              const idx = prev.findIndex(
                (s) => s.id === "attack-surface-discovery"
              );
              if (idx === -1) return prev;

              const updated = [...prev];
              const subagent = updated[idx]!;
              const newMessages = [...subagent.messages];

              // Add text content
              if (text && text.trim()) {
                setThinking(false);
                const lastMsg = newMessages[newMessages.length - 1];
                if (lastMsg && lastMsg.role === "assistant") {
                  newMessages[newMessages.length - 1] = {
                    ...lastMsg,
                    content: (lastMsg.content || "") + text,
                  };
                } else {
                  newMessages.push({
                    role: "assistant",
                    content: text,
                    createdAt: new Date(),
                  });
                }
              }

              // Add tool calls
              if (toolCalls && toolCalls.length > 0) {
                setThinking(false);
                for (const tc of toolCalls) {
                  // AI SDK v5.x uses 'input' instead of 'args'
                  const args = (tc as any).input as
                    | Record<string, unknown>
                    | undefined;
                  const toolDescription =
                    typeof args?.toolCallDescription === "string"
                      ? args.toolCallDescription
                      : tc.toolName;
                  newMessages.push({
                    role: "tool",
                    status: "pending",
                    toolCallId: tc.toolCallId,
                    toolName: tc.toolName,
                    content: toolDescription,
                    args: args,
                    createdAt: new Date(),
                  });
                }
              }

              // Update tool results
              if (toolResults && toolResults.length > 0) {
                setThinking(true);
                for (const tr of toolResults) {
                  const msgIdx = newMessages.findIndex(
                    (m) => m.role === "tool" && m.toolCallId === tr.toolCallId
                  );
                  if (msgIdx !== -1) {
                    const existingMsg = newMessages[msgIdx] as ToolUIMessage;
                    // Use the stored toolCallDescription (in content) if available, fallback to toolName
                    const description =
                      typeof existingMsg.content === "string" &&
                      existingMsg.content !== existingMsg.toolName
                        ? existingMsg.content
                        : existingMsg.toolName || "tool";
                    newMessages[msgIdx] = {
                      ...existingMsg,
                      status: "completed",
                      content: `✓ ${description}`,
                      result: (tr as any).output, // Store the tool output
                    };
                  }
                }
              }

              updated[idx] = { ...subagent, messages: newMessages };
              return updated;
            });
          },

          // Keep onDiscoveryStream as backup for real-time text streaming
          onDiscoveryStream: (chunk) => {
            // Only handle text-delta for real-time streaming effect
            // Other chunk types are handled by onStepFinish for reliability
            if (chunk.type === "text-delta" && chunk.textDelta) {
              currentDiscoveryText += chunk.textDelta;

              // Debounce updates - only update every 100ms worth of text
              if (currentDiscoveryText.trim()) {
                setSubagents((prev) => {
                  const idx = prev.findIndex(
                    (s) => s.id === "attack-surface-discovery"
                  );
                  if (idx === -1) return prev;

                  const updated = [...prev];
                  const subagent = updated[idx]!;
                  const lastMsg =
                    subagent.messages[subagent.messages.length - 1];

                  if (lastMsg && lastMsg.role === "assistant") {
                    const newMessages = [...subagent.messages];
                    newMessages[newMessages.length - 1] = {
                      ...lastMsg,
                      content: currentDiscoveryText,
                    };
                    updated[idx] = { ...subagent, messages: newMessages };
                  } else {
                    updated[idx] = {
                      ...subagent,
                      messages: [
                        ...subagent.messages,
                        {
                          role: "assistant",
                          content: currentDiscoveryText,
                          createdAt: new Date(),
                        },
                      ],
                    };
                  }
                  return updated;
                });
              }
            } else if (chunk.type === "step-finish") {
              // Reset accumulated text at step boundaries
              currentDiscoveryText = "";
            }
          },

          onPentestAgentSpawn: (info: SubAgentSpawnInfo) => {
            setSubagents((prev) => {
              const updated = prev.map((s) =>
                s.id === "attack-surface-discovery" && s.status === "pending"
                  ? { ...s, status: "completed" as const }
                  : s
              );
              return [
                ...updated,
                {
                  id: info.id,
                  name: info.name,
                  type: "pentest" as const,
                  target: info.target,
                  messages: [],
                  status: "pending" as const,
                  createdAt: new Date(),
                },
              ];
            });
          },

          onPentestAgentStream: (event: SubAgentStreamEvent) => {
            if (event.type === "step-finish" && event.data) {
              const { text, toolCalls, toolResults, usage } = event.data;

              if (usage) {
                const stepTokens =
                  (usage.inputTokens ?? 0) + (usage.outputTokens ?? 0);
                if (stepTokens > 0)
                  addTokenUsage(
                    usage.inputTokens ?? 0,
                    usage.outputTokens ?? 0
                  );
              }

              setSubagents((prev) => {
                const idx = prev.findIndex((s) => s.id === event.agentId);
                if (idx === -1) return prev;

                const updated = [...prev];
                const subagent = updated[idx]!;
                const newMessages = [...subagent.messages];

                if (text && text.trim()) {
                  const lastMsg = newMessages[newMessages.length - 1];
                  if (lastMsg && lastMsg.role === "assistant") {
                    newMessages[newMessages.length - 1] = {
                      ...lastMsg,
                      content: (lastMsg.content || "") + text,
                    };
                  } else {
                    newMessages.push({
                      role: "assistant",
                      content: text,
                      createdAt: new Date(),
                    });
                  }
                }

                if (toolCalls && toolCalls.length > 0) {
                  for (const tc of toolCalls) {
                    // AI SDK v5.x uses 'input' instead of 'args'
                    const args = (tc as any).input as
                      | Record<string, unknown>
                      | undefined;
                    const toolDescription =
                      typeof args?.toolCallDescription === "string"
                        ? args.toolCallDescription
                        : tc.toolName;
                    newMessages.push({
                      role: "tool",
                      status: "pending",
                      toolCallId: tc.toolCallId,
                      toolName: tc.toolName,
                      content: toolDescription,
                      args: args,
                      createdAt: new Date(),
                    });
                  }
                }

                if (toolResults && toolResults.length > 0) {
                  for (const tr of toolResults) {
                    const msgIdx = newMessages.findIndex(
                      (m) => m.role === "tool" && m.toolCallId === tr.toolCallId
                    );
                    if (msgIdx !== -1) {
                      const existingMsg = newMessages[msgIdx] as ToolUIMessage;
                      // Use the stored toolCallDescription (in content) if available, fallback to toolName
                      const description =
                        typeof existingMsg.content === "string" &&
                        existingMsg.content !== existingMsg.toolName
                          ? existingMsg.content
                          : existingMsg.toolName || "tool";
                      newMessages[msgIdx] = {
                        ...existingMsg,
                        status: "completed",
                        content: `✓ ${description}`,
                        result: (tr as any).output, // Store the tool output
                      };
                    }
                  }
                }

                updated[idx] = { ...subagent, messages: newMessages };
                return updated;
              });
            }
          },

          onPentestAgentComplete: (
            agentId: string,
            agentResult: MetaVulnerabilityTestResult
          ) => {
            setSubagents((prev) =>
              prev.map((sub) =>
                sub.id === agentId
                  ? {
                      ...sub,
                      status: agentResult.error ? "failed" : "completed",
                      messages: [
                        ...sub.messages,
                        {
                          role: "assistant",
                          content: `${
                            agentResult.findingsCount > 0 ? "✅" : "⚪"
                          } ${agentResult.summary}`,
                          createdAt: new Date(),
                        },
                      ],
                    }
                  : sub
              )
            );
          },

          onProgress: (status: StreamlinedPentestProgress) => {
            // Progress updates can be shown in UI if needed
          },
        });

        // Handle completion
        if (result.success) {
          if (
            (result.reportPath && existsSync(result.reportPath)) ||
            existsSync(
              result.session.rootPath + "/comprehensive-pentest-report.md"
            )
          ) {
            setIsCompleted(true);
          }
        }

        setThinking(false);
        setIsExecuting(false);
      } catch (error) {
        setThinking(false);
        setIsExecuting(false);

        if (error instanceof Error && error.name === "AbortError") {
          // Aborted by user
        } else {
          setError(
            error instanceof Error ? error.message : "Unknown error occurred"
          );
        }
      }
    },
    [model.id, addTokenUsage, setThinking, setIsExecuting]
  );

  // Open report
  const openReport = useCallback(() => {
    if (session?.rootPath) {
      const reportPath = `${session.rootPath}/comprehensive-pentest-report.md`;
      if (existsSync(reportPath)) {
        exec(`open "${reportPath}"`);
      } else {
        exec(`open "${session.rootPath}"`);
      }
    }
  }, [session?.rootPath]);

  // Handle back navigation
  const handleBack = useCallback(() => {
    if (abortController) {
      abortController.abort();
    }
    route.navigate({ type: "base", path: "home" });
  }, [abortController, route]);

  // Loading state
  if (loading) {
    return (
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        alignItems="center"
        justifyContent="center"
        flexGrow={1}
        gap={2}
      >
        <SpinnerDots label="Loading session..." fg="green" />
      </box>
    );
  }

  // Error state
  if (error || !session) {
    return (
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        alignItems="center"
        justifyContent="center"
        flexGrow={1}
        gap={2}
      >
        <text fg="red">Error: {error || "Session not found"}</text>
        <text fg={dimText}>Press ESC to return home</text>
      </box>
    );
  }

  // Driver mode - render DriverDashboard for manual agent orchestration
  if (session.config?.mode === 'driver') {
    return <DriverDashboard session={session} />;
  }

  // Operator mode - render OperatorDashboard for interactive pentesting
  if (session.config?.mode === 'operator') {
    return <OperatorDashboard session={session} isResume={isResume} />;
  }

  // Auto mode - Render SwarmDashboard with streamlined pentest
  return (
    <SwarmDashboard
      subagents={subagents}
      isExecuting={isExecuting}
      startTime={startTime ?? undefined}
      sessionPath={session.rootPath}
      isCompleted={isCompleted}
      onBack={handleBack}
      onViewReport={openReport}
    />
  );
}
