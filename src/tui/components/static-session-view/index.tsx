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
const yellowText = RGBA.fromInts(255, 193, 7, 255);
const redText = RGBA.fromInts(244, 67, 54, 255);

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

  // Initialization progress tracking
  type InitStatus = 'pending' | 'in_progress' | 'done' | 'error';
  const [initProgress, setInitProgress] = useState<{
    loadingSession: InitStatus;
    initializingWorkspace: InitStatus;
    startingPipeline: InitStatus;
  }>({
    loadingSession: 'in_progress',
    initializingWorkspace: 'pending',
    startingPipeline: 'pending',
  });

  // Activity log for streaming telemetry
  interface ActivityEntry {
    id: string;
    timestamp: Date;
    type: 'tool_start' | 'tool_complete' | 'finding' | 'stage_transition' | 'message';
    icon: string;
    color: typeof greenBullet;
    title: string;
    detail?: string;
    agentId?: string;
    stage?: StaticAnalysisStage;
  }
  const [activityLog, setActivityLog] = useState<ActivityEntry[]>([]);
  const [showActivityStream, setShowActivityStream] = useState(true);
  const [currentTool, setCurrentTool] = useState<string | undefined>();

  // Activity buckets for sparkline visualization (last 30 seconds, 1-second buckets)
  const [activityBuckets, setActivityBuckets] = useState<number[]>(new Array(30).fill(0));

  // Shift activity buckets every second
  useEffect(() => {
    if (!isExecuting) return;

    const interval = setInterval(() => {
      setActivityBuckets(prev => [...prev.slice(1), 0]);
    }, 1000);

    return () => clearInterval(interval);
  }, [isExecuting]);

  // Load session on mount with progress tracking
  useEffect(() => {
    async function loadSession() {
      try {
        setInitProgress(prev => ({ ...prev, loadingSession: 'in_progress' }));

        const loadedSession = await Session.get(sessionId || runId);
        if (!loadedSession) {
          setInitProgress(prev => ({ ...prev, loadingSession: 'error' }));
          setError(`Session not found: ${sessionId || runId}`);
          setLoading(false);
          return;
        }

        setInitProgress(prev => ({
          ...prev,
          loadingSession: 'done',
          initializingWorkspace: 'in_progress'
        }));

        // Brief delay to show workspace initialization
        await new Promise(resolve => setTimeout(resolve, 100));

        setInitProgress(prev => ({
          ...prev,
          initializingWorkspace: 'done',
          startingPipeline: 'in_progress'
        }));

        setSession(loadedSession);
        setLoading(false);
      } catch (e) {
        setInitProgress(prev => ({ ...prev, loadingSession: 'error' }));
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

                    // Add to activity log and increment activity bucket for sparkline
                    const friendlyToolName = tc.toolName.replace(/_/g, ' ').replace(/([A-Z])/g, ' $1').trim();
                    setCurrentTool(friendlyToolName);
                    setActivityBuckets(prev => {
                      const next = [...prev];
                      next[next.length - 1]++;
                      return next;
                    });
                    setActivityLog(prev => [...prev.slice(-50), {
                      id: tc.toolCallId,
                      timestamp: new Date(),
                      type: 'tool_start' as const,
                      icon: '◐',
                      color: yellowText,
                      title: `Running ${friendlyToolName}`,
                      detail: toolDescription,
                      agentId: event.agentId,
                    }]);
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

                      // Update activity log - mark tool complete
                      setCurrentTool(undefined);
                      setActivityLog(prev => prev.map(entry =>
                        entry.id === tr.toolCallId
                          ? {
                              ...entry,
                              type: 'tool_complete' as const,
                              icon: '✓',
                              color: greenBullet,
                              title: entry.title.replace('Running ', ''),
                            }
                          : entry
                      ));
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

            // Add stage transition to activity log
            setActivityLog(prev => [...prev.slice(-50), {
              id: `stage-${agentResult.stage}-${Date.now()}`,
              timestamp: new Date(),
              type: 'stage_transition' as const,
              icon: agentResult.success ? '✓' : '✗',
              color: agentResult.success ? greenBullet : redText,
              title: `Stage ${agentResult.stage} ${agentResult.success ? 'completed' : 'failed'}`,
              detail: agentResult.summary,
              stage: agentResult.stage,
            }]);
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

  // Helper to get status icon and color
  const getInitIcon = (status: InitStatus) => {
    switch (status) {
      case 'pending': return '○';
      case 'in_progress': return '◐';
      case 'done': return '✓';
      case 'error': return '✗';
      default: return '○';
    }
  };

  const getInitColor = (status: InitStatus) => {
    switch (status) {
      case 'pending': return dimText;
      case 'in_progress': return yellowText;
      case 'done': return greenBullet;
      case 'error': return redText;
      default: return dimText;
    }
  };

  // Loading state with step-by-step progress
  if (loading) {
    return (
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        alignItems="center"
        justifyContent="center"
        flexGrow={1}
        gap={1}
      >
        <SpinnerDots label="Initializing analysis..." fg="green" />

        <box flexDirection="column" gap={0} marginTop={1}>
          <box flexDirection="row" gap={1}>
            <text fg={getInitColor(initProgress.loadingSession)}>
              {getInitIcon(initProgress.loadingSession)}
            </text>
            <text fg={initProgress.loadingSession === 'in_progress' ? creamText : dimText}>
              Loading session...
            </text>
          </box>

          <box flexDirection="row" gap={1}>
            <text fg={getInitColor(initProgress.initializingWorkspace)}>
              {getInitIcon(initProgress.initializingWorkspace)}
            </text>
            <text fg={initProgress.initializingWorkspace === 'in_progress' ? creamText : dimText}>
              Initializing workspace...
            </text>
          </box>

          <box flexDirection="row" gap={1}>
            <text fg={getInitColor(initProgress.startingPipeline)}>
              {getInitIcon(initProgress.startingPipeline)}
            </text>
            <text fg={initProgress.startingPipeline === 'in_progress' ? creamText : dimText}>
              Starting pipeline...
            </text>
          </box>
        </box>
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
      currentTool={currentTool}
      activityLog={activityLog}
      activityBuckets={activityBuckets}
      showActivityStream={showActivityStream}
      onToggleActivityStream={() => setShowActivityStream(prev => !prev)}
      onBack={handleBack}
      onViewReport={openReport}
    />
  );
}
