import { useState, useEffect, useCallback, useRef } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { useRoute } from "../../context/route";
import { useAgent } from "../../agentProvider";
import SwarmDashboard, {
  type UIMessage,
  type Subagent,
} from "../swarm-dashboard";
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

// Streaming update interval (ms) - throttle UI updates to prevent flashing
const STREAM_UPDATE_INTERVAL = 80;

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
  useEffect(() => {
    if (session && !hasStarted && !loading && !isResume) {
      setHasStarted(true);
      startPentest(session);
    }
  }, [session, hasStarted, loading, isResume]);

  // Start the pentest
  const startPentest = useCallback(
    async (execSession: Session.SessionInfo) => {
      setIsExecuting(true);
      setThinking(true);
      setStartTime(new Date());

      const controller = new AbortController();
      setAbortController(controller);

      // Throttled streaming state for all agents (discovery + pentest)
      const pendingTextByAgent: Map<string, string> = new Map();
      let flushTimer: ReturnType<typeof setTimeout> | null = null;

      const flushPendingText = () => {
        if (pendingTextByAgent.size === 0) return;

        setSubagents((prev) => {
          let updated = [...prev];
          for (const [agentId, text] of pendingTextByAgent) {
            const idx = updated.findIndex((s) => s.id === agentId);
            if (idx === -1) continue;

            const subagent = updated[idx]!;
            const newMessages = [...subagent.messages];
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

            updated[idx] = { ...subagent, messages: newMessages };
          }
          return updated;
        });

        pendingTextByAgent.clear();
      };

      const scheduleFlush = () => {
        if (flushTimer) return; // Already scheduled
        flushTimer = setTimeout(() => {
          flushTimer = null;
          flushPendingText();
        }, STREAM_UPDATE_INTERVAL);
      };

      // Helper to simulate streaming for text that arrives all at once
      const streamTextToAgent = (agentId: string, text: string, onComplete?: () => void) => {
        let charIndex = 0;
        const streamInterval = setInterval(() => {
          const chunkSize = 3 + Math.floor(Math.random() * 3);
          const chunk = text.slice(charIndex, charIndex + chunkSize);
          charIndex += chunkSize;

          if (chunk) {
            pendingTextByAgent.set(
              agentId,
              (pendingTextByAgent.get(agentId) || "") + chunk
            );
            scheduleFlush();
          }

          if (charIndex >= text.length) {
            clearInterval(streamInterval);
            if (flushTimer) {
              clearTimeout(flushTimer);
              flushTimer = null;
            }
            flushPendingText();
            onComplete?.();
          }
        }, 15);
      };

      // Helper to stream tool description text
      const streamToolDescription = (agentId: string, toolCallId: string, text: string) => {
        let charIndex = 0;
        const streamInterval = setInterval(() => {
          const chunkSize = 2 + Math.floor(Math.random() * 3);
          const chunk = text.slice(charIndex, charIndex + chunkSize);
          charIndex += chunkSize;

          if (chunk) {
            setSubagents((prev) => {
              const idx = prev.findIndex((s) => s.id === agentId);
              if (idx === -1) return prev;

              const updated = [...prev];
              const subagent = updated[idx]!;
              const newMessages = [...subagent.messages];

              const msgIdx = newMessages.findIndex(
                (m) => m.role === "tool" && m.toolCallId === toolCallId
              );
              if (msgIdx !== -1) {
                const existingMsg = newMessages[msgIdx] as ToolUIMessage;
                newMessages[msgIdx] = {
                  ...existingMsg,
                  content: (existingMsg.content || "") + chunk,
                };
              }

              updated[idx] = { ...subagent, messages: newMessages };
              return updated;
            });
          }

          if (charIndex >= text.length) {
            clearInterval(streamInterval);
          }
        }, 20);
      };

      // Helper to stream tool completion (prepend checkmark)
      const streamToolCompletion = (agentId: string, toolCallId: string) => {
        const checkmark = "✓ ";
        let charIndex = 0;
        const streamInterval = setInterval(() => {
          const chunk = checkmark.slice(charIndex, charIndex + 1);
          charIndex += 1;

          if (chunk) {
            setSubagents((prev) => {
              const idx = prev.findIndex((s) => s.id === agentId);
              if (idx === -1) return prev;

              const updated = [...prev];
              const subagent = updated[idx]!;
              const newMessages = [...subagent.messages];

              const msgIdx = newMessages.findIndex(
                (m) => m.role === "tool" && m.toolCallId === toolCallId
              );
              if (msgIdx !== -1) {
                const existingMsg = newMessages[msgIdx] as ToolUIMessage;
                // Prepend to existing content
                if (charIndex === 1) {
                  // First char - start prepending
                  newMessages[msgIdx] = {
                    ...existingMsg,
                    content: chunk + existingMsg.content,
                  };
                } else {
                  // Continue prepending (insert after previous prepended chars)
                  const content = existingMsg.content || "";
                  newMessages[msgIdx] = {
                    ...existingMsg,
                    content: content.slice(0, charIndex - 1) + chunk + content.slice(charIndex - 1),
                  };
                }
              }

              updated[idx] = { ...subagent, messages: newMessages };
              return updated;
            });
          }

          if (charIndex >= checkmark.length) {
            clearInterval(streamInterval);
          }
        }, 30);
      };

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

          // Handle step-finish for token usage and tool calls/results
          // Text content comes via onDiscoveryStream for real-time streaming
          onDiscoveryStepFinish: (step) => {
            const stepTokens =
              (step.usage?.inputTokens ?? 0) + (step.usage?.outputTokens ?? 0);
            if (stepTokens > 0)
              addTokenUsage(
                step.usage.inputTokens ?? 0,
                step.usage.outputTokens ?? 0
              );

            const { toolCalls, toolResults } = step;
            const agentId = "attack-surface-discovery";

            // Handle tool calls - add them immediately, then stream the description
            if (toolCalls && toolCalls.length > 0) {
              setThinking(false);
              for (const tc of toolCalls) {
                const args = (tc as any).input as
                  | Record<string, unknown>
                  | undefined;
                const toolDescription =
                  typeof args?.toolCallDescription === "string"
                    ? args.toolCallDescription
                    : tc.toolName;

                // Add tool message with empty content, then stream the description
                setSubagents((prev) => {
                  const idx = prev.findIndex((s) => s.id === agentId);
                  if (idx === -1) return prev;

                  const updated = [...prev];
                  const subagent = updated[idx]!;
                  updated[idx] = {
                    ...subagent,
                    messages: [
                      ...subagent.messages,
                      {
                        role: "tool",
                        status: "pending",
                        toolCallId: tc.toolCallId,
                        toolName: tc.toolName,
                        content: "",
                        args: args,
                        createdAt: new Date(),
                      },
                    ],
                  };
                  return updated;
                });

                // Stream the tool description
                streamToolDescription(agentId, tc.toolCallId, toolDescription);
              }
            }

            // Handle tool results - update status and stream completion message
            if (toolResults && toolResults.length > 0) {
              setThinking(true);
              for (const tr of toolResults) {
                setSubagents((prev) => {
                  const idx = prev.findIndex((s) => s.id === agentId);
                  if (idx === -1) return prev;

                  const updated = [...prev];
                  const subagent = updated[idx]!;
                  const newMessages = [...subagent.messages];

                  const msgIdx = newMessages.findIndex(
                    (m) => m.role === "tool" && m.toolCallId === tr.toolCallId
                  );
                  if (msgIdx !== -1) {
                    const existingMsg = newMessages[msgIdx] as ToolUIMessage;
                    newMessages[msgIdx] = {
                      ...existingMsg,
                      status: "completed",
                      content: existingMsg.content, // Keep current content, will stream checkmark
                      result: (tr as any).output,
                    };
                  }

                  updated[idx] = { ...subagent, messages: newMessages };
                  return updated;
                });

                // Stream the checkmark prefix to the tool
                streamToolCompletion(agentId, tr.toolCallId);
              }
            }
          },

          // Real-time text streaming for discovery agent with throttling
          onDiscoveryStream: (chunk) => {
            if (chunk.type === "text-delta" && chunk.textDelta) {
              setThinking(false);
              // Buffer the text and schedule a throttled flush
              const agentId = "attack-surface-discovery";
              const existing = pendingTextByAgent.get(agentId) || "";
              pendingTextByAgent.set(agentId, existing + chunk.textDelta);
              scheduleFlush();
            } else if (chunk.type === "step-finish") {
              // Flush any pending text immediately at step boundaries
              if (flushTimer) {
                clearTimeout(flushTimer);
                flushTimer = null;
              }
              flushPendingText();
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
            // Handle real-time text streaming with throttling
            if (event.type === "text-delta" && event.data?.textDelta) {
              setThinking(false);
              // Buffer the text and schedule a throttled flush
              const existing = pendingTextByAgent.get(event.agentId) || "";
              pendingTextByAgent.set(event.agentId, existing + event.data.textDelta);
              scheduleFlush();
            }

            // Handle step-finish for tool calls and token usage
            if (event.type === "step-finish" && event.data) {
              // Flush any pending text immediately before processing step-finish
              if (flushTimer) {
                clearTimeout(flushTimer);
                flushTimer = null;
              }
              flushPendingText();
              const { text, toolCalls, toolResults, usage } = event.data;
              const agentId = event.agentId;

              // Handle text from this step - add as assistant message if present
              if (text) {
                setSubagents((prev) => {
                  const idx = prev.findIndex((s) => s.id === agentId);
                  if (idx === -1) return prev;

                  const updated = [...prev];
                  const subagent = updated[idx]!;
                  const newMessages = [...subagent.messages];
                  const lastMsg = newMessages[newMessages.length - 1];

                  if (lastMsg && lastMsg.role === "assistant") {
                    // Append to existing assistant message
                    newMessages[newMessages.length - 1] = {
                      ...lastMsg,
                      content: (lastMsg.content || "") + text,
                    };
                  } else {
                    // Create new assistant message
                    newMessages.push({
                      role: "assistant",
                      content: text,
                      createdAt: new Date(),
                    });
                  }

                  updated[idx] = { ...subagent, messages: newMessages };
                  return updated;
                });

                // Clear pending text to avoid duplication
                pendingTextByAgent.delete(agentId);
              }

              if (usage) {
                const stepTokens =
                  (usage.inputTokens ?? 0) + (usage.outputTokens ?? 0);
                if (stepTokens > 0)
                  addTokenUsage(
                    usage.inputTokens ?? 0,
                    usage.outputTokens ?? 0
                  );
              }

              // Handle tool calls - add with empty content, then stream description
              if (toolCalls && toolCalls.length > 0) {
                for (const tc of toolCalls) {
                  const args = (tc as any).input as
                    | Record<string, unknown>
                    | undefined;
                  const toolDescription =
                    typeof args?.toolCallDescription === "string"
                      ? args.toolCallDescription
                      : tc.toolName;

                  // Add tool message with empty content
                  setSubagents((prev) => {
                    const idx = prev.findIndex((s) => s.id === agentId);
                    if (idx === -1) return prev;

                    const updated = [...prev];
                    const subagent = updated[idx]!;
                    updated[idx] = {
                      ...subagent,
                      messages: [
                        ...subagent.messages,
                        {
                          role: "tool",
                          status: "pending",
                          toolCallId: tc.toolCallId,
                          toolName: tc.toolName,
                          content: "",
                          args: args,
                          createdAt: new Date(),
                        },
                      ],
                    };
                    return updated;
                  });

                  // Stream the tool description
                  streamToolDescription(agentId, tc.toolCallId, toolDescription);
                }
              }

              // Handle tool results - update status and stream checkmark
              if (toolResults && toolResults.length > 0) {
                for (const tr of toolResults) {
                  setSubagents((prev) => {
                    const idx = prev.findIndex((s) => s.id === agentId);
                    if (idx === -1) return prev;

                    const updated = [...prev];
                    const subagent = updated[idx]!;
                    const newMessages = [...subagent.messages];

                    const msgIdx = newMessages.findIndex(
                      (m) => m.role === "tool" && m.toolCallId === tr.toolCallId
                    );
                    if (msgIdx !== -1) {
                      const existingMsg = newMessages[msgIdx] as ToolUIMessage;
                      newMessages[msgIdx] = {
                        ...existingMsg,
                        status: "completed",
                        content: existingMsg.content,
                        result: (tr as any).output,
                      };
                    }

                    updated[idx] = { ...subagent, messages: newMessages };
                    return updated;
                  });

                  // Stream the checkmark
                  streamToolCompletion(agentId, tr.toolCallId);
                }
              }
            }
          },

          onPentestAgentComplete: (
            agentId: string,
            agentResult: MetaVulnerabilityTestResult
          ) => {
            // Stream out the completion summary using the same throttled mechanism
            const prefix = agentResult.findingsCount > 0 ? "✅ " : "⚪ ";
            const fullText = prefix + agentResult.summary;

            // Add empty assistant message first, then stream into it
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
                          content: "",
                          createdAt: new Date(),
                        },
                      ],
                    }
                  : sub
              )
            );

            // Stream the text character by character with small delays
            let charIndex = 0;
            const streamInterval = setInterval(() => {
              // Stream ~3-5 characters at a time for smooth effect
              const chunkSize = 3 + Math.floor(Math.random() * 3);
              const chunk = fullText.slice(charIndex, charIndex + chunkSize);
              charIndex += chunkSize;

              if (chunk) {
                pendingTextByAgent.set(
                  agentId,
                  (pendingTextByAgent.get(agentId) || "") + chunk
                );
                scheduleFlush();
              }

              if (charIndex >= fullText.length) {
                clearInterval(streamInterval);
                // Final flush
                if (flushTimer) {
                  clearTimeout(flushTimer);
                  flushTimer = null;
                }
                flushPendingText();
              }
            }, 20); // 20ms between chunks for smooth streaming
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
    route.navigate({ type: "base", path: "home" });
    // if (isExecuting && abortController) {
    //   abortController.abort();
    // } else {
    //   route.navigate({ type: "base", path: "home" });
    // }
  }, [isExecuting, abortController, route]);

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

  // Render SwarmDashboard
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
