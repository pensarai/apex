import { useState, useEffect, useCallback } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { useRoute } from "../../context/route";
import { useAgent } from "../../context/agent";
import SwarmDashboard, {
  type UIMessage,
  type Subagent,
} from "../swarm-dashboard";
import OperatorDashboard from "../operator-dashboard";
import { Session } from "../../../core/session";
import {
  loadSessionState,
  type UISubagent,
} from "../../../core/session/loader";
import { runAgent as runAttackSurfaceAgent } from "../../../core/agent/attackSurfaceAgent/agent";
import {
  runPentestPipeline,
  type PipelineResult,
  type PipelineInput,
} from "../../../core/agent/orchestrator/pipeline";
import { generatePentestReport } from "../../../core/agent/reportGeneratorAgent";
import type {
  AttackSurfaceAnalysisResults,
  PentestTarget,
} from "../../../core/agent/attackSurfaceAgent/types";
import type {
  SubAgentManifest,
  Finding,
} from "../../../core/agent/subagent/types";
import type { RunSubAgentResult } from "../../../core/agent/subagent";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
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
      if (mode === "operator" || mode === "driver") {
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

  // Start the pentest using the new pipeline
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

        // Phase 1: Run Attack Surface Discovery
        const { streamResult } = await runAttackSurfaceAgent({
          target: execSession.targets[0] || "",
          objective:
            "Comprehensive attack surface discovery and target identification",
          model: model.id,
          session: execSession,
          abortSignal: controller.signal,
          onStepFinish: (step) => {
            const stepTokens =
              (step.usage?.inputTokens ?? 0) + (step.usage?.outputTokens ?? 0);
            if (stepTokens > 0)
              addTokenUsage(
                step.usage.inputTokens ?? 0,
                step.usage.outputTokens ?? 0,
              );

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

              // Add tool calls
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
                    (m) => m.role === "tool" && m.toolCallId === tr.toolCallId,
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
                      content: `+ ${description}`,
                      result: (tr as any).output,
                    };
                  }
                }
              }

              updated[idx] = { ...subagent, messages: newMessages };
              return updated;
            });
          },
        });

        // Consume the stream with real-time UI updates
        for await (const chunk of streamResult.fullStream) {
          // Handle text-delta for real-time streaming
          if (chunk.type === "text-delta" && "text" in chunk) {
            currentDiscoveryText += chunk.text;
            const deltaText = chunk.text;

            // Update UI in real-time as text streams in
            setThinking(false);
            setSubagents((prev) => {
              const idx = prev.findIndex(
                (s) => s.id === "attack-surface-discovery",
              );
              if (idx === -1) return prev;

              const updated = [...prev];
              const subagent = updated[idx]!;
              const newMessages = [...subagent.messages];

              // Append to existing assistant message or create new one
              const lastMsg = newMessages[newMessages.length - 1];
              if (lastMsg && lastMsg.role === "assistant") {
                newMessages[newMessages.length - 1] = {
                  ...lastMsg,
                  content: (lastMsg.content || "") + deltaText,
                };
              } else {
                newMessages.push({
                  role: "assistant",
                  content: deltaText,
                  createdAt: new Date(),
                });
              }

              updated[idx] = { ...subagent, messages: newMessages };
              return updated;
            });
          }

          // Handle tool-call for real-time tool call display
          if (chunk.type === "tool-call") {
            setThinking(false);
            const tc = chunk as any;
            setSubagents((prev) => {
              const idx = prev.findIndex(
                (s) => s.id === "attack-surface-discovery",
              );
              if (idx === -1) return prev;

              const updated = [...prev];
              const subagent = updated[idx]!;
              const newMessages = [...subagent.messages];

              // Check if tool call already exists to avoid duplicates
              const exists = newMessages.some(
                (m) => m.role === "tool" && m.toolCallId === tc.toolCallId,
              );
              if (exists) return prev;

              // AI SDK uses 'input' not 'args' for tool-call chunks
              const args = (tc.input ?? tc.args) as
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

              updated[idx] = { ...subagent, messages: newMessages };
              return updated;
            });
          }

          // Handle tool-result for real-time tool result display
          if (chunk.type === "tool-result") {
            setThinking(true);
            const tr = chunk as any;
            setSubagents((prev) => {
              const idx = prev.findIndex(
                (s) => s.id === "attack-surface-discovery",
              );
              if (idx === -1) return prev;

              const updated = [...prev];
              const subagent = updated[idx]!;
              const newMessages = [...subagent.messages];

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
                  content: `+ ${description}`,
                  // AI SDK uses 'output' not 'result' for tool-result chunks
                  result: tr.output ?? tr.result,
                };
              } else {
                // Tool result arrived before tool call - create as completed
                newMessages.push({
                  role: "tool",
                  status: "completed",
                  toolCallId: tr.toolCallId,
                  toolName: tr.toolName || "tool",
                  content: `+ ${tr.toolName || "tool"}`,
                  result: tr.output ?? tr.result,
                  createdAt: new Date(),
                });
              }

              updated[idx] = { ...subagent, messages: newMessages };
              return updated;
            });
          }
        }

        // Mark discovery as complete
        setSubagents((prev) =>
          prev.map((s) =>
            s.id === "attack-surface-discovery"
              ? { ...s, status: "completed" as const }
              : s,
          ),
        );

        // Read attack surface results
        const resultsPath = join(
          execSession.rootPath,
          "attack-surface-results.json",
        );
        if (!existsSync(resultsPath)) {
          setThinking(false);
          setIsExecuting(false);
          return;
        }

        const resultsData = readFileSync(resultsPath, "utf-8");
        const results: AttackSurfaceAnalysisResults = JSON.parse(resultsData);
        const targets = results.targets || [];

        if (targets.length === 0) {
          setThinking(false);
          setIsExecuting(false);
          return;
        }

        // Phase 2: Run the new pentest pipeline
        const pipelineResult = await runPentestPipeline({
          attackSurfacePath: resultsPath,
          session: execSession,
          model: model.id,
          workspace: execSession.rootPath,
          whiteboxMode: false,
          concurrencyLimit: 10,
          abortSignal: controller.signal,
          onOrchestratorComplete: (manifest: SubAgentManifest) => {
            // Add subagents for each spawned agent in the manifest
            for (const config of manifest.subagents) {
              setSubagents((prev) => [
                ...prev,
                {
                  id: config.id,
                  name: `${config.vulnerabilityClass} on ${config.endpoint}`,
                  type: "pentest" as const,
                  target: config.endpoint,
                  messages: [],
                  status: "pending" as const,
                  createdAt: new Date(),
                },
              ]);
            }
          },
          onSubAgentStart: (
            subagentId: string,
            endpoint: string,
            vulnClass: string,
          ) => {
            setSubagents((prev) =>
              prev.map((sub) =>
                sub.id === subagentId
                  ? { ...sub, status: "running" as const }
                  : sub,
              ),
            );
          },
          onSubAgentStep: (subagentId: string, step) => {
            // Step-based updates (backup for anything missed by onChunk)
            // onChunk handles real-time streaming, this ensures completeness
            setSubagents((prev) => {
              const idx = prev.findIndex((s) => s.id === subagentId);
              if (idx === -1) return prev;

              const updated = [...prev];
              const subagent = updated[idx]!;
              const newMessages = [...subagent.messages];
              let hasChanges = false;

              // Add tool calls only if they don't already exist
              if (step.toolCalls && step.toolCalls.length > 0) {
                for (const tc of step.toolCalls) {
                  const exists = newMessages.some(
                    (m) => m.role === "tool" && m.toolCallId === tc.toolCallId,
                  );
                  if (!exists) {
                    const args = tc.args as Record<string, unknown> | undefined;
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
                    hasChanges = true;
                  }
                }
              }

              // Update tool results (always mark as completed)
              if (step.toolResults && step.toolResults.length > 0) {
                for (const tr of step.toolResults) {
                  const msgIdx = newMessages.findIndex(
                    (m) => m.role === "tool" && m.toolCallId === tr.toolCallId,
                  );
                  if (msgIdx !== -1) {
                    const existingMsg = newMessages[msgIdx] as ToolUIMessage;
                    // Always update to completed (handles race conditions)
                    if (existingMsg.status !== "completed") {
                      const description =
                        typeof existingMsg.content === "string" &&
                        existingMsg.content !== existingMsg.toolName
                          ? existingMsg.content
                          : existingMsg.toolName || "tool";
                      newMessages[msgIdx] = {
                        ...existingMsg,
                        status: "completed",
                        content: `+ ${description}`,
                        result: tr.result,
                      };
                      hasChanges = true;
                    }
                  } else {
                    // Tool result arrived but tool call doesn't exist - create as completed
                    newMessages.push({
                      role: "tool",
                      status: "completed",
                      toolCallId: tr.toolCallId,
                      toolName: tr.toolName,
                      content: `+ ${tr.toolName || "tool"}`,
                      result: tr.result,
                      createdAt: new Date(),
                    });
                    hasChanges = true;
                  }
                }
              }

              if (!hasChanges) return prev;
              updated[idx] = { ...subagent, messages: newMessages };
              return updated;
            });
          },
          onSubAgentChunk: (subagentId: string, chunk) => {
            // Real-time chunk streaming for tool calls
            setSubagents((prev) => {
              const idx = prev.findIndex((s) => s.id === subagentId);
              if (idx === -1) return prev;

              const updated = [...prev];
              const subagent = updated[idx]!;
              const newMessages = [...subagent.messages];

              if (chunk.type === "text-delta" && chunk.text) {
                setThinking(false);
                const lastMsg = newMessages[newMessages.length - 1];
                if (lastMsg && lastMsg.role === "assistant") {
                  newMessages[newMessages.length - 1] = {
                    ...lastMsg,
                    content: (lastMsg.content || "") + chunk.text,
                  };
                } else {
                  newMessages.push({
                    role: "assistant",
                    content: chunk.text,
                    createdAt: new Date(),
                  });
                }
              } else if (chunk.type === "tool-call") {
                setThinking(false);
                // Check if tool call already exists to avoid duplicates
                const exists = newMessages.some(
                  (m) => m.role === "tool" && m.toolCallId === chunk.toolCallId,
                );
                if (!exists) {
                  const args = chunk.args as
                    | Record<string, unknown>
                    | undefined;
                  const toolDescription =
                    typeof args?.toolCallDescription === "string"
                      ? args.toolCallDescription
                      : chunk.toolName || "tool";
                  newMessages.push({
                    role: "tool",
                    status: "pending",
                    toolCallId: chunk.toolCallId!,
                    toolName: chunk.toolName!,
                    content: toolDescription,
                    args: args,
                    createdAt: new Date(),
                  });
                }
              } else if (chunk.type === "tool-result") {
                setThinking(true);
                const msgIdx = newMessages.findIndex(
                  (m) => m.role === "tool" && m.toolCallId === chunk.toolCallId,
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
                    content: `+ ${description}`,
                    result: chunk.result,
                  };
                } else {
                  // Tool result arrived before tool call - create as completed
                  newMessages.push({
                    role: "tool",
                    status: "completed",
                    toolCallId: chunk.toolCallId!,
                    toolName: chunk.toolName || "tool",
                    content: `+ ${chunk.toolName || "tool"}`,
                    result: chunk.result,
                    createdAt: new Date(),
                  });
                }
              }

              updated[idx] = { ...subagent, messages: newMessages };
              return updated;
            });
          },
          onSubAgentComplete: (result: RunSubAgentResult) => {
            const findingsCount = result.findings?.length || 0;
            const hasError = !!result.error;

            setSubagents((prev) =>
              prev.map((sub) =>
                sub.id === result.subagentId
                  ? {
                      ...sub,
                      status: hasError ? "failed" : "completed",
                      messages: [
                        ...sub.messages,
                        {
                          role: "assistant",
                          content: `${findingsCount > 0 ? "+" : "-"} ${result.attackResult?.summary || "Complete"}`,
                          createdAt: new Date(),
                        },
                      ],
                    }
                  : sub,
              ),
            );
          },
        });

        // Phase 3: Generate report
        if (pipelineResult.success && pipelineResult.allFindings.length > 0) {
          await generatePentestReport({
            sessionRootPath: execSession.rootPath,
            sessionId: execSession.id,
            target: execSession.targets[0] || "",
            startTime: execSession.time.created.toString(),
            reportTitle: `Penetration Test Report - ${execSession.targets[0]}`,
            includeMethodology: true,
          });
        }

        // Check if report was generated
        const reportPath = join(
          execSession.rootPath,
          "comprehensive-pentest-report.md",
        );
        if (existsSync(reportPath)) {
          setIsCompleted(true);
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

  // Driver mode - deprecated, fall through to auto mode
  // Note: driver mode was removed as part of codebase cleanup

  // Operator mode - render OperatorDashboard for interactive pentesting
  if (session.config?.mode === "operator") {
    return <OperatorDashboard session={session} isResume={isResume} />;
  }

  // Auto mode - Render SwarmDashboard with pipeline pentest
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
