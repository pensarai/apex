import { useState, useEffect, useCallback, useRef } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { useRoute } from "../../context/route";
import { useAgent } from "../../context/agent";
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
import type { VulnerabilityClass } from "../../../core/agent/orchestrator/types";
import {
  runMetaVulnerabilityTestAgent,
  type MetaVulnerabilityTestResult,
} from "../../../core/agent/metaTestingAgent";
import { saveAgentMessages } from "../../../core/agent/metaTestingAgent";
import { existsSync, readFileSync } from "fs";
import { exec } from "child_process";
import { join } from "path";
import { SpinnerDots } from "../sprites";
import type { AttackSurfaceAnalysisResults } from "../../../core/agent/attackSurfaceAgent/types";

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

/** Type for tool call chunks from AI SDK stream */
interface StreamToolCall {
  toolCallId: string;
  toolName: string;
  input?: Record<string, unknown>;
  args?: Record<string, unknown>;
}

/** Type for tool result chunks from AI SDK stream */
interface StreamToolResult {
  toolCallId: string;
  toolName: string;
  output?: unknown;
  result?: unknown;
}

/** Type guard for stream chunks */
interface StreamChunk {
  type: string;
  text?: string;
  toolCallId?: string;
  toolName?: string;
  [key: string]: unknown;
}

function isStreamChunk(chunk: unknown): chunk is StreamChunk {
  return typeof chunk === "object" && chunk !== null && "type" in chunk;
}

/** Type for step-finish event data with usage info */
interface StepFinishData {
  usage?: { inputTokens?: number; outputTokens?: number };
  text?: string;
  [key: string]: unknown;
}

interface SessionViewProps {
  sessionId: string;
  /** If true, load existing session state without starting a new pentest */
  isResume?: boolean;
  /** If true, open an auto-mode session in operator mode */
  openAsOperator?: boolean;
}

export default function SessionView({
  sessionId,
  isResume = false,
  openAsOperator = false,
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

  // Per-agent abort controllers for individual kill capability
  const agentAbortControllers = useRef<Map<string, AbortController>>(new Map());

  // Ref to access current subagents without adding to dependency arrays
  const subagentsRef = useRef(subagents);
  subagentsRef.current = subagents;

  const killAgent = useCallback(
    (agentId: string) => {
      const controller = agentAbortControllers.current.get(agentId);
      if (controller) {
        controller.abort();
        setSubagents((prev) => {
          const agent = prev.find((a) => a.id === agentId);
          // Persist canceled status to disk so it survives session resume
          if (agent && session) {
            try {
              const messages = agent.messages.map((m) => ({
                role: m.role,
                content: m.content,
              }));
              saveAgentMessages(session.rootPath, agent.id, messages, {
                target: agent.target,
                status: "canceled",
              });
            } catch (_e) {
              // Best-effort persistence — don't break the kill flow
            }
          }
          return prev.map((a) =>
            a.id === agentId ? { ...a, status: "canceled" as const } : a,
          );
        });
      }
    },
    [session],
  );

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
            const loadedSubagents: Subagent[] = state.subagents.map((s) => ({
              id: s.id,
              name: s.name,
              type: s.type,
              target: s.target,
              messages: s.messages,
              createdAt: s.createdAt,
              status: s.status,
              resumeInfo: s.resumeInfo,
            }));
            setSubagents(loadedSubagents);
            setStartTime(new Date(loadedSession.time.created));

            if (state.hasReport) {
              // COMPLETED — static display, no restart
              setIsCompleted(true);
              setHasStarted(true);
            } else if (state.attackSurfaceResults) {
              // MID-PENTEST — discovery done, pentest was interrupted
              // Show loaded state as-is, don't restart from discovery
              setHasStarted(true);
            } else if (state.interruptedDuringDiscovery) {
              // INTERRUPTED DISCOVERY — show partial logs, don't auto-restart
              setHasStarted(true);
            }
            // else: PRE-DISCOVERY — let auto-start restart from scratch
          } catch (e) {
            console.error("Failed to load session state:", e);
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

  // Start pentest once session is loaded
  // Skip auto-start for operator/driver modes - they have their own start logic
  useEffect(() => {
    if (session && !hasStarted && !loading) {
      const mode = session.config?.mode;
      if (mode === "operator" || mode === "driver" || openAsOperator) return;
      setHasStarted(true);
      startPentest(session);
    }
  }, [session, hasStarted, loading, openAsOperator]);

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
    async (
      execSession: Session.SessionInfo,
      previousDiscoveryResults?: AttackSurfaceAnalysisResults,
    ) => {
      setIsExecuting(true);
      setThinking(true);
      setStartTime(new Date());

      const controller = new AbortController();
      setAbortController(controller);

      let currentDiscoveryText = "";
      // Track accumulated text per pentest agent for real-time streaming
      const pentestAgentTexts = new Map<string, string>();

      try {
        // Add or reuse discovery subagent — preserve existing messages on resume
        setSubagents((prev) => {
          const existingIdx = prev.findIndex(
            (s) => s.id === "attack-surface-discovery",
          );
          if (existingIdx !== -1) {
            // Reuse existing entry: keep old messages, update status
            const updated = [...prev];
            updated[existingIdx] = {
              ...updated[existingIdx]!,
              status: previousDiscoveryResults
                ? ("completed" as const)
                : ("pending" as const),
            };
            return updated;
          }
          return [
            ...prev,
            {
              id: "attack-surface-discovery",
              name: "Attack Surface Discovery",
              type: "attack-surface" as const,
              target: execSession.targets[0],
              messages: [],
              status: "pending" as const,
              createdAt: new Date(),
            },
          ];
        });

        // Run streamlined pentest
        const result = await runStreamlinedPentest({
          target: execSession.targets[0],
          model: model.id,
          session: execSession,
          sessionConfig: execSession.config,
          abortSignal: controller.signal,
          previousDiscoveryResults,
          onAgentAbortControllerCreated: (agentId, abortCtrl) => {
            agentAbortControllers.current.set(agentId, abortCtrl);
          },

          // Use onStepFinish for UI updates (like metavuln agent does)
          // This is more reliable than raw stream chunks which can be interrupted
          onDiscoveryStepFinish: (step) => {
            const stepTokens =
              (step.usage?.inputTokens ?? 0) + (step.usage?.outputTokens ?? 0);
            if (stepTokens > 0)
              addTokenUsage(
                step.usage.inputTokens ?? 0,
                step.usage.outputTokens ?? 0,
              );

            // Update messages from step data (same pattern as onPentestAgentStream)
            const { text, toolCalls, toolResults } = step;

            setSubagents((prev) => {
              const idx = prev.findIndex(
                (s) => s.id === "attack-surface-discovery",
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

              // Add tool calls (check if not already exists to avoid duplicates)
              if (toolCalls && toolCalls.length > 0) {
                setThinking(false);
                for (const tc of toolCalls) {
                  const exists = newMessages.some(
                    (m) => m.role === "tool" && m.toolCallId === tc.toolCallId,
                  );
                  if (!exists) {
                    // AI SDK v5.x uses 'input' instead of 'args'
                    const args = (tc as unknown as StreamToolCall).input;
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
              }

              // Update tool results
              if (toolResults && toolResults.length > 0) {
                setThinking(true);
                for (const tr of toolResults) {
                  const msgIdx = newMessages.findIndex(
                    (m) => m.role === "tool" && m.toolCallId === tr.toolCallId,
                  );
                  if (msgIdx !== -1) {
                    const existingMsg = newMessages[msgIdx] as ToolUIMessage;
                    // Always update to completed (handles race conditions)
                    const description =
                      typeof existingMsg.content === "string" &&
                      existingMsg.content !== existingMsg.toolName
                        ? existingMsg.content
                        : existingMsg.toolName || "tool";
                    newMessages[msgIdx] = {
                      ...existingMsg,
                      status: "completed",
                      content: description,
                      result: (tr as unknown as StreamToolResult).output,
                    };
                  } else {
                    // Tool result arrived before tool call - create as completed
                    newMessages.push({
                      role: "tool",
                      status: "completed",
                      toolCallId: tr.toolCallId,
                      toolName: tr.toolName,
                      content: `+ ${tr.toolName || "tool"}`,
                      result: (tr as unknown as StreamToolResult).output,
                      createdAt: new Date(),
                    });
                  }
                }
              }

              updated[idx] = { ...subagent, messages: newMessages };
              return updated;
            });
          },

          // Real-time streaming for discovery agent
          onDiscoveryStream: (chunk: unknown) => {
            if (!isStreamChunk(chunk)) return;
            if (chunk.type === "text-delta" && chunk.text) {
              currentDiscoveryText += chunk.text;
              setThinking(false);

              if (currentDiscoveryText.trim()) {
                setSubagents((prev) => {
                  const idx = prev.findIndex(
                    (s) => s.id === "attack-surface-discovery",
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
            } else if (chunk.type === "tool-call") {
              // Real-time tool call streaming
              setThinking(false);
              const tc = chunk as unknown as StreamToolCall;
              const toolCallId = tc.toolCallId;
              const toolName = tc.toolName || "tool";
              const args = tc.input ?? tc.args;
              const toolDescription =
                typeof args?.toolCallDescription === "string"
                  ? args.toolCallDescription
                  : toolName;

              setSubagents((prev) => {
                const idx = prev.findIndex(
                  (s) => s.id === "attack-surface-discovery",
                );
                if (idx === -1) return prev;

                const updated = [...prev];
                const subagent = updated[idx]!;
                const newMessages = [...subagent.messages];

                // Check if tool call already exists
                const exists = newMessages.some(
                  (m) => m.role === "tool" && m.toolCallId === toolCallId,
                );
                if (!exists) {
                  newMessages.push({
                    role: "tool",
                    status: "pending",
                    toolCallId,
                    toolName,
                    content: toolDescription,
                    args,
                    createdAt: new Date(),
                  });
                }

                updated[idx] = { ...subagent, messages: newMessages };
                return updated;
              });
            } else if (chunk.type === "tool-result") {
              // Real-time tool result streaming
              setThinking(true);
              const tr = chunk as unknown as StreamToolResult;
              const toolCallId = tr.toolCallId;
              const toolName = tr.toolName || "tool";
              const result = tr.output ?? tr.result;

              setSubagents((prev) => {
                const idx = prev.findIndex(
                  (s) => s.id === "attack-surface-discovery",
                );
                if (idx === -1) return prev;

                const updated = [...prev];
                const subagent = updated[idx]!;
                const newMessages = [...subagent.messages];

                const msgIdx = newMessages.findIndex(
                  (m) => m.role === "tool" && m.toolCallId === toolCallId,
                );
                if (msgIdx !== -1) {
                  const existingMsg = newMessages[msgIdx] as ToolUIMessage;
                  const description =
                    typeof existingMsg.content === "string" &&
                    existingMsg.content !== existingMsg.toolName
                      ? existingMsg.content
                      : existingMsg.toolName || "tool";
                  newMessages[msgIdx] = {
                    ...existingMsg,
                    status: "completed",
                    content: description,
                    result,
                  };
                } else {
                  // Tool result arrived before tool call
                  newMessages.push({
                    role: "tool",
                    status: "completed",
                    toolCallId,
                    toolName,
                    content: `+ ${toolName}`,
                    result,
                    createdAt: new Date(),
                  });
                }

                updated[idx] = { ...subagent, messages: newMessages };
                return updated;
              });
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
                  : s,
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
            const agentId = event.agentId;
            const eventData = event.data as Record<string, unknown> | undefined;

            // Handle real-time text streaming
            if (event.type === "text-delta" && eventData?.text) {
              const currentText = pentestAgentTexts.get(agentId) || "";
              const newText = currentText + (eventData.text as string);
              pentestAgentTexts.set(agentId, newText);

              if (newText.trim()) {
                setSubagents((prev) => {
                  const idx = prev.findIndex((s) => s.id === agentId);
                  if (idx === -1) return prev;

                  const updated = [...prev];
                  const subagent = updated[idx]!;
                  const lastMsg =
                    subagent.messages[subagent.messages.length - 1];

                  if (lastMsg && lastMsg.role === "assistant") {
                    const newMessages = [...subagent.messages];
                    newMessages[newMessages.length - 1] = {
                      ...lastMsg,
                      content: newText,
                    };
                    updated[idx] = { ...subagent, messages: newMessages };
                  } else {
                    updated[idx] = {
                      ...subagent,
                      messages: [
                        ...subagent.messages,
                        {
                          role: "assistant",
                          content: newText,
                          createdAt: new Date(),
                        },
                      ],
                    };
                  }
                  return updated;
                });
              }
            }
            // Handle real-time tool call streaming
            else if (event.type === "tool-call") {
              const tc = event.data as StreamToolCall;
              const toolCallId = tc.toolCallId;
              const toolName = tc.toolName || "tool";
              const args = tc.input ?? tc.args;
              const toolDescription =
                typeof args?.toolCallDescription === "string"
                  ? args.toolCallDescription
                  : toolName;

              setSubagents((prev) => {
                const idx = prev.findIndex((s) => s.id === agentId);
                if (idx === -1) return prev;

                const updated = [...prev];
                const subagent = updated[idx]!;
                const newMessages = [...subagent.messages];

                // Check if tool call already exists
                const exists = newMessages.some(
                  (m) => m.role === "tool" && m.toolCallId === toolCallId,
                );
                if (!exists) {
                  newMessages.push({
                    role: "tool",
                    status: "pending",
                    toolCallId,
                    toolName,
                    content: toolDescription,
                    args,
                    createdAt: new Date(),
                  });
                }

                updated[idx] = { ...subagent, messages: newMessages };
                return updated;
              });
            }
            // Handle real-time tool result streaming
            else if (event.type === "tool-result") {
              const tr = event.data as StreamToolResult;
              const toolCallId = tr.toolCallId;
              const toolName = tr.toolName || "tool";
              const result = tr.output ?? tr.result;

              setSubagents((prev) => {
                const idx = prev.findIndex((s) => s.id === agentId);
                if (idx === -1) return prev;

                const updated = [...prev];
                const subagent = updated[idx]!;
                const newMessages = [...subagent.messages];

                const msgIdx = newMessages.findIndex(
                  (m) => m.role === "tool" && m.toolCallId === toolCallId,
                );
                if (msgIdx !== -1) {
                  const existingMsg = newMessages[msgIdx] as ToolUIMessage;
                  const description =
                    typeof existingMsg.content === "string" &&
                    existingMsg.content !== existingMsg.toolName
                      ? existingMsg.content
                      : existingMsg.toolName || "tool";
                  newMessages[msgIdx] = {
                    ...existingMsg,
                    status: "completed",
                    content: description,
                    result,
                  };
                } else {
                  // Tool result arrived before tool call
                  newMessages.push({
                    role: "tool",
                    status: "completed",
                    toolCallId,
                    toolName,
                    content: `+ ${toolName}`,
                    result,
                    createdAt: new Date(),
                  });
                }

                updated[idx] = { ...subagent, messages: newMessages };
                return updated;
              });
            }
            // Handle step-finish for token tracking and resetting text accumulator
            else if (event.type === "step-finish" && eventData) {
              const { usage } = eventData as StepFinishData;

              if (usage) {
                const stepTokens =
                  (usage.inputTokens ?? 0) + (usage.outputTokens ?? 0);
                if (stepTokens > 0)
                  addTokenUsage(
                    usage.inputTokens ?? 0,
                    usage.outputTokens ?? 0,
                  );
              }

              // Reset accumulated text at step boundaries
              pentestAgentTexts.set(agentId, "");
            }
          },

          onPentestAgentComplete: (
            agentId: string,
            agentResult: MetaVulnerabilityTestResult,
          ) => {
            setSubagents((prev) =>
              prev.map((sub) =>
                sub.id === agentId && sub.status !== "canceled"
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
                  : sub,
              ),
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
              result.session.rootPath + "/comprehensive-pentest-report.md",
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
            error instanceof Error ? error.message : "Unknown error occurred",
          );
        }
      }
    },
    [model.id, addTokenUsage, setThinking, setIsExecuting],
  );

  // Resume a paused agent individually
  const resumeAgent = useCallback(
    async (agentId: string) => {
      if (!session) return;

      // Read current subagents via ref to avoid stale closure
      const paused = subagentsRef.current.find(
        (s) => s.id === agentId && s.status === "paused",
      );
      if (!paused) return;

      // Discovery agents — resume the full pipeline, preserving old messages.
      // If discovery completed before interruption, skip it entirely.
      if (paused.type === "attack-surface") {
        let previousResults: AttackSurfaceAnalysisResults | undefined;
        const resultsPath = join(
          session.rootPath,
          "attack-surface-results.json",
        );
        if (existsSync(resultsPath)) {
          try {
            previousResults = JSON.parse(readFileSync(resultsPath, "utf-8"));
          } catch {
            // ignored
          }
        }
        await startPentest(session, previousResults);
        return;
      }

      if (!paused.resumeInfo) return;

      const { target, objective, vulnerabilityClass, authenticationInfo } =
        paused.resumeInfo;

      // Update status to pending (running)
      setSubagents((prev) =>
        prev.map((s) =>
          s.id === agentId ? { ...s, status: "pending" as const } : s,
        ),
      );

      setIsExecuting(true);
      setThinking(true);

      // Track text accumulation for streaming
      let accumulatedText = "";

      try {
        const result = await runMetaVulnerabilityTestAgent({
          input: {
            target,
            objective,
            vulnerabilityClass: vulnerabilityClass as VulnerabilityClass,
            authenticationInfo,
            authenticationInstructions:
              session.config?.authenticationInstructions,
            outcomeGuidance:
              session.config?.outcomeGuidance ||
              "Find and document vulnerabilities",
            session: {
              id: session.id,
              rootPath: session.rootPath,
              findingsPath: session.findingsPath,
              logsPath: session.logsPath,
              pocsPath: session.rootPath + "/pocs",
            },
            sessionConfig: {
              enableCvssScoring: session.config?.enableCvssScoring,
              cvssModel: session.config?.cvssModel,
            },
          },
          model: model.id,
          abortSignal: abortController?.signal,
          onChunk: (chunk) => {
            if (chunk.type === "text-delta" && chunk.text) {
              accumulatedText += chunk.text;
              setThinking(false);

              if (accumulatedText.trim()) {
                setSubagents((prev) => {
                  const idx = prev.findIndex((s) => s.id === agentId);
                  if (idx === -1) return prev;

                  const updated = [...prev];
                  const subagent = updated[idx]!;
                  const lastMsg =
                    subagent.messages[subagent.messages.length - 1];

                  if (lastMsg && lastMsg.role === "assistant") {
                    const newMessages = [...subagent.messages];
                    newMessages[newMessages.length - 1] = {
                      ...lastMsg,
                      content: accumulatedText,
                    };
                    updated[idx] = { ...subagent, messages: newMessages };
                  } else {
                    updated[idx] = {
                      ...subagent,
                      messages: [
                        ...subagent.messages,
                        {
                          role: "assistant",
                          content: accumulatedText,
                          createdAt: new Date(),
                        },
                      ],
                    };
                  }
                  return updated;
                });
              }
            } else if (chunk.type === "tool-call") {
              setThinking(false);
              const tc = chunk as unknown as StreamToolCall;
              const toolCallId = tc.toolCallId;
              const toolName = tc.toolName || "tool";
              const args = tc.input ?? tc.args;
              const toolDescription =
                typeof args?.toolCallDescription === "string"
                  ? args.toolCallDescription
                  : toolName;

              setSubagents((prev) => {
                const idx = prev.findIndex((s) => s.id === agentId);
                if (idx === -1) return prev;

                const updated = [...prev];
                const subagent = updated[idx]!;
                const newMessages = [...subagent.messages];

                const exists = newMessages.some(
                  (m) => m.role === "tool" && m.toolCallId === toolCallId,
                );
                if (!exists) {
                  newMessages.push({
                    role: "tool",
                    status: "pending",
                    toolCallId,
                    toolName,
                    content: toolDescription,
                    args,
                    createdAt: new Date(),
                  });
                }

                updated[idx] = { ...subagent, messages: newMessages };
                return updated;
              });
            } else if (chunk.type === "tool-result") {
              setThinking(true);
              const tr = chunk as unknown as StreamToolResult;
              const toolCallId = tr.toolCallId;
              const toolName = tr.toolName || "tool";
              const resultData = tr.output ?? tr.result;

              setSubagents((prev) => {
                const idx = prev.findIndex((s) => s.id === agentId);
                if (idx === -1) return prev;

                const updated = [...prev];
                const subagent = updated[idx]!;
                const newMessages = [...subagent.messages];

                const msgIdx = newMessages.findIndex(
                  (m) => m.role === "tool" && m.toolCallId === toolCallId,
                );
                if (msgIdx !== -1) {
                  const existingMsg = newMessages[msgIdx] as ToolUIMessage;
                  const description =
                    typeof existingMsg.content === "string" &&
                    existingMsg.content !== existingMsg.toolName
                      ? existingMsg.content
                      : existingMsg.toolName || "tool";
                  newMessages[msgIdx] = {
                    ...existingMsg,
                    status: "completed",
                    content: description,
                    result: resultData,
                  };
                } else {
                  newMessages.push({
                    role: "tool",
                    status: "completed",
                    toolCallId,
                    toolName,
                    content: `+ ${toolName}`,
                    result: resultData,
                    createdAt: new Date(),
                  });
                }

                updated[idx] = { ...subagent, messages: newMessages };
                return updated;
              });
            }
          },
          onStepFinish: (step) => {
            // Token tracking
            const usage = step.usage;
            if (usage) {
              const stepTokens =
                (usage.inputTokens ?? 0) + (usage.outputTokens ?? 0);
              if (stepTokens > 0)
                addTokenUsage(usage.inputTokens ?? 0, usage.outputTokens ?? 0);
            }
            // Reset accumulated text at step boundaries
            accumulatedText = "";
          },
        });

        // On completion, update status
        setSubagents((prev) =>
          prev.map((s) =>
            s.id === agentId
              ? {
                  ...s,
                  status: result.error
                    ? ("failed" as const)
                    : ("completed" as const),
                  resumeInfo: undefined,
                  messages: [
                    ...s.messages,
                    {
                      role: "assistant" as const,
                      content: `${result.findingsCount > 0 ? "✅" : "⚪"} ${result.summary}`,
                      createdAt: new Date(),
                    },
                  ],
                }
              : s,
          ),
        );
      } catch (error) {
        setSubagents((prev) =>
          prev.map((s) =>
            s.id === agentId
              ? { ...s, status: "failed" as const, resumeInfo: undefined }
              : s,
          ),
        );
      }

      setThinking(false);
      // Only set isExecuting=false if no other agents are still running
      const stillRunning = subagentsRef.current.some(
        (s) => s.status === "pending" && s.id !== agentId,
      );
      if (!stillRunning) {
        setIsExecuting(false);
      }
    },
    [
      session,
      model.id,
      abortController,
      addTokenUsage,
      setThinking,
      setIsExecuting,
      startPentest,
    ],
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
  if (session.config?.mode === "driver") {
    return <DriverDashboard session={session} />;
  }

  // Operator mode - render OperatorDashboard for interactive pentesting
  if (session.config?.mode === "operator" || openAsOperator) {
    return (
      <OperatorDashboard
        session={session}
        isResume={isResume}
        openAsOperator={openAsOperator}
      />
    );
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
      onKillAgent={killAgent}
      onResumeAgent={resumeAgent}
    />
  );
}
