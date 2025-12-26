import { useState, useEffect, useCallback } from "react";
import { RGBA } from "@opentui/core";
import { useRoute } from "../../context/route";
import { useAgent } from "../../agentProvider";
import StaticDashboard, {
  type UIMessage,
  type StaticSubagent,
} from "../static-dashboard";
import { Session } from "../../../core/session";
import { runStaticOrchestrator } from "../../../core/static/orchestrator";
import type {
  StaticAnalysisProgress,
  StaticSubagentSpawnInfo,
  StaticSubagentStreamEvent,
  StaticAgentResult,
  StaticFinding,
  StaticAnalysisStage,
} from "../../../core/static/types";
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

interface StaticSessionViewProps {
  runId: string;
  sessionId?: string;
}

export default function StaticSessionView({
  runId,
  sessionId,
}: StaticSessionViewProps) {
  const route = useRoute();
  const { model, setThinking, isExecuting, addTokenUsage, setIsExecuting } =
    useAgent();

  // Session state
  const [session, setSession] = useState<Session.SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Execution state
  const [subagents, setSubagents] = useState<StaticSubagent[]>([]);
  const [isCompleted, setIsCompleted] = useState(false);
  const [abortController, setAbortController] = useState<AbortController | null>(null);
  const [startTime, setStartTime] = useState<Date | null>(null);
  const [hasStarted, setHasStarted] = useState(false);

  // Analysis state
  const [currentStage, setCurrentStage] = useState<StaticAnalysisStage | undefined>();
  const [completedStages, setCompletedStages] = useState<StaticAnalysisStage[]>([]);
  const [findings, setFindings] = useState<StaticFinding[]>([]);
  const [reportPaths, setReportPaths] = useState<{ sarif?: string; md?: string; json?: string }>({});

  // Load session on mount
  useEffect(() => {
    async function loadSession() {
      try {
        const loadedSession = await Session.get(sessionId || runId);
        if (!loadedSession) {
          setError(`Session not found: ${sessionId || runId}`);
          setLoading(false);
          return;
        }
        setSession(loadedSession);
        setLoading(false);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load session");
        setLoading(false);
      }
    }
    loadSession();
  }, [sessionId, runId]);

  // Start analysis once session is loaded
  useEffect(() => {
    if (session && !hasStarted && !loading) {
      setHasStarted(true);
      startAnalysis(session);
    }
  }, [session, hasStarted, loading]);

  // Start the static analysis
  const startAnalysis = useCallback(
    async (execSession: Session.SessionInfo) => {
      // Validate required config
      const repoPath = execSession.config?.staticConfig?.repoPath;
      if (!repoPath) {
        setError("No repository path configured");
        return;
      }

      setIsExecuting(true);
      setThinking(true);
      setStartTime(new Date());

      const controller = new AbortController();
      setAbortController(controller);

      try {
        const result = await runStaticOrchestrator({
          repoPath,
          repoUrl: execSession.config?.staticConfig?.repoUrl,
          ref: execSession.config?.staticConfig?.ref || "HEAD",
          model: model.id,
          session: execSession,
          sessionConfig: execSession.config?.staticConfig,
          abortSignal: controller.signal,

          onProgress: (progress: StaticAnalysisProgress) => {
            if (progress.phase !== 'starting' && progress.phase !== 'complete') {
              setCurrentStage(progress.phase as StaticAnalysisStage);
            }
            if (progress.stagesCompleted !== undefined) {
              setCompletedStages(prev => {
                // Don't duplicate
                return prev;
              });
            }
          },

          onAgentSpawn: (info: StaticSubagentSpawnInfo) => {
            setSubagents(prev => [
              ...prev,
              {
                id: info.id,
                name: info.name,
                type: info.stage,
                stageNumber: info.stageNumber,
                messages: [],
                status: "pending" as const,
                createdAt: new Date(),
              },
            ]);
          },

          onAgentStream: (event: StaticSubagentStreamEvent) => {
            if (event.type === "step-finish" && event.data) {
              const { text, toolCalls, toolResults, usage } = event.data;

              if (usage) {
                const stepTokens = (usage.promptTokens ?? 0) + (usage.completionTokens ?? 0);
                if (stepTokens > 0) {
                  addTokenUsage(usage.promptTokens ?? 0, usage.completionTokens ?? 0);
                }
              }

              setSubagents(prev => {
                const idx = prev.findIndex(s => s.id === event.agentId);
                if (idx === -1) return prev;

                const updated = [...prev];
                const subagent = updated[idx]!;
                const newMessages = [...subagent.messages];

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

                if (toolCalls && toolCalls.length > 0) {
                  setThinking(false);
                  for (const tc of toolCalls) {
                    const args = (tc as any).input as Record<string, unknown> | undefined;
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
                  setThinking(true);
                  for (const tr of toolResults) {
                    const msgIdx = newMessages.findIndex(
                      m => m.role === "tool" && m.toolCallId === tr.toolCallId
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
                        content: `✓ ${description}`,
                        result: (tr as any).output,
                      };
                    }
                  }
                }

                updated[idx] = { ...subagent, messages: newMessages };
                return updated;
              });
            }
          },

          onAgentComplete: (agentId: string, agentResult: StaticAgentResult) => {
            setSubagents(prev =>
              prev.map(sub =>
                sub.id === agentId
                  ? {
                      ...sub,
                      status: agentResult.success ? "completed" : "failed",
                      duration_ms: agentResult.duration_ms,
                      artifacts: agentResult.artifacts,
                      messages: [
                        ...sub.messages,
                        {
                          role: "assistant" as const,
                          content: `${agentResult.success ? "✅" : "❌"} ${agentResult.summary}`,
                          createdAt: new Date(),
                        },
                      ],
                    }
                  : sub
              )
            );

            // Update completed stages
            if (agentResult.success) {
              setCompletedStages(prev => {
                if (prev.includes(agentResult.stage)) return prev;
                return [...prev, agentResult.stage];
              });
            }
          },
        });

        // Handle completion
        setFindings(result.findings);
        setReportPaths(result.reportPaths);
        setCompletedStages(result.state.completed_stages);
        setIsCompleted(true);

        setThinking(false);
        setIsExecuting(false);
      } catch (error) {
        setThinking(false);
        setIsExecuting(false);

        if (error instanceof Error && error.name === "AbortError") {
          // Aborted by user
        } else {
          setError(error instanceof Error ? error.message : "Unknown error occurred");
        }
      }
    },
    [model.id, addTokenUsage, setThinking, setIsExecuting]
  );

  // Open report
  const openReport = useCallback(() => {
    if (reportPaths.md && existsSync(reportPaths.md)) {
      exec(`open "${reportPaths.md}"`);
    } else if (session?.rootPath) {
      exec(`open "${session.rootPath}"`);
    }
  }, [reportPaths.md, session?.rootPath]);

  // Handle back navigation
  const handleBack = useCallback(() => {
    route.navigate({ type: "base", path: "home" });
  }, [route]);

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

  // Render StaticDashboard
  return (
    <StaticDashboard
      subagents={subagents}
      isExecuting={isExecuting}
      startTime={startTime ?? undefined}
      sessionPath={session.rootPath}
      isCompleted={isCompleted}
      findings={findings}
      currentStage={currentStage}
      completedStages={completedStages}
      repoPath={session.config?.staticConfig?.repoPath}
      reportPaths={reportPaths}
      onBack={handleBack}
      onViewReport={openReport}
    />
  );
}
