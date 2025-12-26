import { useState, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import AgentDisplay, { type DisplayMessage } from "../agent-display";
import { SpinnerDots } from "../sprites";
import type { StaticAnalysisStage, StaticFinding } from "../../../core/static/types";
import { STAGE_ORDER, STAGE_NAMES } from "../../../core/static/types";

// Color palette
export const greenBullet = RGBA.fromInts(76, 175, 80, 255);
export const creamText = RGBA.fromInts(255, 248, 220, 255);
export const dimText = RGBA.fromInts(120, 120, 120, 255);
export const darkBg = RGBA.fromInts(10, 10, 10, 255);
export const yellowText = RGBA.fromInts(255, 193, 7, 255);
export const redText = RGBA.fromInts(244, 67, 54, 255);
export const orangeText = RGBA.fromInts(255, 152, 0, 255);

// Re-export DisplayMessage as UIMessage for backwards compatibility
export type UIMessage = DisplayMessage;

// Static subagent type
export interface StaticSubagent {
  id: string;
  name: string;
  type: StaticAnalysisStage;
  stageNumber: number;
  messages: DisplayMessage[];
  createdAt: Date;
  status: "pending" | "completed" | "failed";
  artifacts?: string[];
  duration_ms?: number;
}

interface StaticDashboardProps {
  subagents: StaticSubagent[];
  isExecuting: boolean;
  startTime?: Date;
  sessionPath?: string;
  isCompleted?: boolean;
  findings?: StaticFinding[];
  currentStage?: StaticAnalysisStage;
  completedStages?: StaticAnalysisStage[];
  repoPath?: string;
  reportPaths?: {
    sarif?: string;
    md?: string;
    json?: string;
  };
  onBack?: () => void;
  onViewReport?: () => void;
}

export default function StaticDashboard({
  subagents,
  isExecuting,
  startTime,
  sessionPath,
  isCompleted,
  findings = [],
  currentStage,
  completedStages = [],
  repoPath,
  reportPaths,
  onBack,
  onViewReport,
}: StaticDashboardProps) {
  const [currentView, setCurrentView] = useState<"overview" | "detail" | "findings">("overview");
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [focusedIndex, setFocusedIndex] = useState(0);

  // Computed metrics
  const metrics = useMemo(() => {
    const bySeverity = {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
    };

    return {
      totalFindings: findings.length,
      activeAgents: subagents.filter(s => s.status === "pending").length,
      completedAgents: subagents.filter(s => s.status === "completed").length,
      totalStages: 8,
      bySeverity,
      duration: startTime ? Math.floor((Date.now() - startTime.getTime()) / 1000) : 0,
    };
  }, [findings, subagents, startTime]);

  // Get currently selected agent for detail view
  const selectedAgent = useMemo(
    () => selectedAgentId ? subagents.find(s => s.id === selectedAgentId) : null,
    [subagents, selectedAgentId]
  );

  // Keyboard navigation
  useKeyboard((key) => {
    if (currentView === "overview") {
      // F to toggle findings view
      if (key.name === "f" || key.name === "F") {
        if (findings.length > 0) {
          setCurrentView("findings");
        }
        return;
      }

      // ESC to exit
      if (key.name === "escape") {
        onBack?.();
        return;
      }

      // Tab/Arrow navigation between stage cards
      const stageCount = subagents.length;
      if (stageCount === 0) return;

      if (key.name === "tab" && !key.shift) {
        setFocusedIndex(prev => (prev + 1) % stageCount);
        return;
      }
      if ((key.name === "tab" && key.shift) || key.name === "left") {
        setFocusedIndex(prev => (prev - 1 + stageCount) % stageCount);
        return;
      }
      if (key.name === "right") {
        setFocusedIndex(prev => (prev + 1) % stageCount);
        return;
      }

      // Enter to drill into agent
      if (key.name === "return") {
        if (subagents[focusedIndex]) {
          setSelectedAgentId(subagents[focusedIndex]!.id);
          setCurrentView("detail");
        } else if (isCompleted && onViewReport) {
          onViewReport();
        }
        return;
      }
    } else if (currentView === "detail" || currentView === "findings") {
      // ESC to return to overview
      if (key.name === "escape") {
        setCurrentView("overview");
        setSelectedAgentId(null);
        return;
      }
    }
  });

  // Agent detail view
  if (currentView === "detail" && selectedAgent) {
    return <AgentDetailView agent={selectedAgent} onBack={() => { setCurrentView("overview"); setSelectedAgentId(null); }} />;
  }

  // Findings view
  if (currentView === "findings") {
    return <FindingsView findings={findings} onBack={() => setCurrentView("overview")} />;
  }

  // Overview view
  return (
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {/* Header */}
      <box
        width="100%"
        flexDirection="row"
        justifyContent="space-between"
        padding={1}
        border={["bottom"]}
        borderColor={greenBullet}
      >
        <box flexDirection="column">
          <text fg={creamText}>Static Analysis Pipeline</text>
          <text fg={dimText}>{repoPath}</text>
        </box>
        <box flexDirection="row" gap={2}>
          {isExecuting && currentStage && (
            <SpinnerDots label={`Stage: ${STAGE_NAMES[currentStage]}`} fg="green" />
          )}
          {isCompleted && <text fg={greenBullet}>✓ Analysis Complete</text>}
        </box>
      </box>

      {/* Main content area */}
      <box flexDirection="row" flexGrow={1} gap={2} padding={1}>
        {/* Left: Pipeline stages */}
        <PipelineView
          stages={STAGE_ORDER}
          currentStage={currentStage}
          completedStages={completedStages}
          subagents={subagents}
        />

        {/* Right: Stage cards or placeholder */}
        <box flexDirection="column" flexGrow={1} gap={1}>
          {subagents.length === 0 ? (
            <box
              flexGrow={1}
              alignItems="center"
              justifyContent="center"
              border
              borderColor={dimText}
              backgroundColor={darkBg}
              padding={2}
            >
              <box flexDirection="column" alignItems="center" gap={1}>
                <SpinnerDots label="Starting analysis..." fg="green" />
                <text fg={dimText}>Pipeline stages will appear here</text>
              </box>
            </box>
          ) : (
            <StageCardGrid
              agents={subagents}
              focusedIndex={focusedIndex}
              onSelectAgent={(id) => {
                setSelectedAgentId(id);
                setCurrentView("detail");
              }}
            />
          )}
        </box>
      </box>

      {/* Completion banner */}
      {isCompleted && reportPaths?.md && (
        <box
          width="100%"
          padding={1}
          backgroundColor={darkBg}
          border
          borderColor={greenBullet}
          flexDirection="column"
          alignItems="center"
          gap={1}
        >
          <text fg={greenBullet}>Static Analysis Completed</text>
          <text fg={dimText}>{reportPaths.md}</text>
          <box flexDirection="row" gap={2}>
            <text>
              <span fg={greenBullet}>[Enter]</span>
              <span fg={dimText}> View Report</span>
            </text>
            <text>
              <span fg={greenBullet}>[F]</span>
              <span fg={dimText}> View Findings ({findings.length})</span>
            </text>
            <text>
              <span fg={greenBullet}>[ESC]</span>
              <span fg={dimText}> Close</span>
            </text>
          </box>
        </box>
      )}

      {/* Bottom: Metrics bar */}
      <MetricsBar
        totalFindings={metrics.totalFindings}
        bySeverity={metrics.bySeverity}
        completedStages={completedStages.length}
        totalStages={metrics.totalStages}
        duration={metrics.duration}
        isExecuting={isExecuting}
      />
    </box>
  );
}

// ============================================================================
// Sub-components
// ============================================================================

interface PipelineViewProps {
  stages: StaticAnalysisStage[];
  currentStage?: StaticAnalysisStage;
  completedStages: StaticAnalysisStage[];
  subagents: StaticSubagent[];
}

function PipelineView({ stages, currentStage, completedStages, subagents }: PipelineViewProps) {
  return (
    <box
      width={28}
      border
      borderColor={greenBullet}
      backgroundColor={darkBg}
      flexDirection="column"
    >
      {/* Header */}
      <box
        flexDirection="row"
        alignItems="center"
        justifyContent="space-between"
        padding={1}
        borderColor={dimText}
        border={["bottom"]}
      >
        <text fg={creamText}>Pipeline</text>
        <text fg={dimText}>{completedStages.length}/8</text>
      </box>

      {/* Stage list */}
      <box flexDirection="column" padding={1} gap={0}>
        {stages.map((stage, i) => {
          const isComplete = completedStages.includes(stage);
          const isCurrent = stage === currentStage;
          const agent = subagents.find(s => s.type === stage);
          const hasFailed = agent?.status === 'failed';

          let icon = "○";
          let color = dimText;

          if (isComplete) {
            icon = "✓";
            color = greenBullet;
          } else if (hasFailed) {
            icon = "✗";
            color = redText;
          } else if (isCurrent) {
            icon = "◐";
            color = yellowText;
          }

          return (
            <box key={stage} flexDirection="row" gap={1}>
              <text fg={color}>{icon}</text>
              <text fg={isCurrent ? creamText : dimText}>
                {i + 1}. {STAGE_NAMES[stage].substring(0, 18)}
              </text>
            </box>
          );
        })}
      </box>
    </box>
  );
}

interface StageCardProps {
  agent: StaticSubagent;
  focused: boolean;
  onSelect: () => void;
}

function StageCard({ agent, focused, onSelect }: StageCardProps) {
  const statusIcon = {
    pending: "◐",
    completed: "✓",
    failed: "✗",
  }[agent.status];

  const statusColor = {
    pending: yellowText,
    completed: greenBullet,
    failed: redText,
  }[agent.status];

  // Get brief activity from last message
  const lastActivity = useMemo(() => {
    const lastMsg = agent.messages[agent.messages.length - 1];
    if (!lastMsg) return "Starting...";
    let text = "";
    if (typeof lastMsg.content === "string") {
      text = lastMsg.content.replace(/\n/g, " ").trim();
    } else {
      return "Working...";
    }
    if (text.length > 45) {
      return text.substring(0, 42) + "...";
    }
    return text;
  }, [agent.messages]);

  // Format duration
  const duration = agent.duration_ms
    ? `${Math.round(agent.duration_ms / 1000)}s`
    : "...";

  return (
    <box
      flexGrow={1}
      flexBasis={0}
      minWidth={36}
      border
      borderColor={focused ? greenBullet : dimText}
      backgroundColor={darkBg}
      flexDirection="column"
      padding={1}
      rowGap={1}
      onMouseDown={onSelect}
    >
      {/* Header row */}
      <box flexDirection="row" alignItems="center" gap={1}>
        <text fg={statusColor}>{statusIcon}</text>
        <text fg={focused ? creamText : dimText}>{agent.name}</text>
      </box>

      {/* Stats row */}
      <box flexDirection="row" gap={2}>
        <text fg={dimText}>
          <span fg={greenBullet}>{agent.messages.length}</span> msgs
        </text>
        <text fg={dimText}>{duration}</text>
      </box>

      {/* Activity */}
      <box height={1} overflow="hidden">
        {agent.status === "pending" ? (
          <SpinnerDots label={lastActivity} fg="green" />
        ) : (
          <text fg={agent.status === "completed" ? greenBullet : dimText}>
            {agent.status === "completed" ? "✓ Complete" : lastActivity}
          </text>
        )}
      </box>
    </box>
  );
}

interface StageCardGridProps {
  agents: StaticSubagent[];
  focusedIndex: number;
  onSelectAgent: (agentId: string) => void;
}

function StageCardGrid({ agents, focusedIndex, onSelectAgent }: StageCardGridProps) {
  // Organize into rows of 2
  const rows = useMemo(() => {
    const result: StaticSubagent[][] = [];
    for (let i = 0; i < agents.length; i += 2) {
      result.push(agents.slice(i, i + 2));
    }
    return result;
  }, [agents]);

  return (
    <scrollbox
      style={{
        rootOptions: { flexGrow: 1, width: "100%" },
        contentOptions: { flexDirection: "column", gap: 1 },
      }}
      stickyScroll={false}
      focused={true}
    >
      {rows.map((row, rowIndex) => (
        <box key={rowIndex} flexDirection="row" gap={1} width="100%">
          {row.map((agent, colIndex) => {
            const flatIndex = rowIndex * 2 + colIndex;
            return (
              <StageCard
                key={agent.id}
                agent={agent}
                focused={flatIndex === focusedIndex}
                onSelect={() => onSelectAgent(agent.id)}
              />
            );
          })}
          {row.length === 1 && <box flexGrow={1} flexBasis={0} minWidth={36} />}
        </box>
      ))}
    </scrollbox>
  );
}

interface MetricsBarProps {
  totalFindings: number;
  bySeverity: { critical: number; high: number; medium: number; low: number };
  completedStages: number;
  totalStages: number;
  duration: number;
  isExecuting: boolean;
}

function MetricsBar({
  totalFindings,
  bySeverity,
  completedStages,
  totalStages,
  duration,
  isExecuting,
}: MetricsBarProps) {
  const formattedDuration = useMemo(() => {
    const mins = Math.floor(duration / 60);
    const secs = duration % 60;
    return `${mins}m ${secs.toString().padStart(2, "0")}s`;
  }, [duration]);

  return (
    <box
      width="100%"
      flexDirection="row"
      justifyContent="space-between"
      borderColor={greenBullet}
      border={["top"]}
      padding={1}
    >
      {/* Left: Findings by severity */}
      <box flexDirection="row" gap={2}>
        <text>
          <span fg={totalFindings > 0 ? greenBullet : dimText}>{totalFindings}</span>
          <span fg={dimText}> findings</span>
        </text>
        {bySeverity.critical > 0 && (
          <text>
            <span fg={redText}>{bySeverity.critical}</span>
            <span fg={dimText}> critical</span>
          </text>
        )}
        {bySeverity.high > 0 && (
          <text>
            <span fg={orangeText}>{bySeverity.high}</span>
            <span fg={dimText}> high</span>
          </text>
        )}
        <text fg={dimText}>|</text>
        <text>
          <span fg={isExecuting ? greenBullet : dimText}>{completedStages}</span>
          <span fg={dimText}>/{totalStages} stages</span>
        </text>
        <text fg={dimText}>|</text>
        <text fg={dimText}>{formattedDuration}</text>
      </box>

      {/* Right: Keyboard hints */}
      <box flexDirection="row" gap={2}>
        <text>
          <span fg={greenBullet}>[F]</span>
          <span fg={dimText}> Findings</span>
        </text>
        <text>
          <span fg={greenBullet}>[Tab]</span>
          <span fg={dimText}> Navigate</span>
        </text>
        <text>
          <span fg={greenBullet}>[Enter]</span>
          <span fg={dimText}> View</span>
        </text>
        <text>
          <span fg={greenBullet}>[ESC]</span>
          <span fg={dimText}> Back</span>
        </text>
      </box>
    </box>
  );
}

interface AgentDetailViewProps {
  agent: StaticSubagent;
  onBack: () => void;
}

function AgentDetailView({ agent, onBack }: AgentDetailViewProps) {
  const statusColor = {
    pending: yellowText,
    completed: greenBullet,
    failed: redText,
  }[agent.status];

  return (
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {/* Header */}
      <box
        width="100%"
        border={["bottom"]}
        borderColor={greenBullet}
        flexDirection="row"
        justifyContent="space-between"
        padding={1}
      >
        <box flexDirection="row" gap={1}>
          <text fg={dimText}>Stage {agent.stageNumber}:</text>
          <text fg={creamText}>{agent.name}</text>
        </box>
        <text fg={statusColor}>{agent.status}</text>
      </box>

      {/* Message content */}
      <AgentDisplay
        messages={agent.messages}
        isStreaming={agent.status === "pending"}
        focused={true}
        paddingLeft={4}
        paddingRight={4}
        contextId={agent.id}
      />

      {/* Footer */}
      <box
        width="100%"
        flexDirection="row"
        justifyContent="space-between"
        border={["top"]}
        borderColor={greenBullet}
        padding={1}
      >
        <text fg={dimText}>
          {agent.messages.length} messages
          {agent.duration_ms && ` • ${Math.round(agent.duration_ms / 1000)}s`}
        </text>
        <text>
          <span fg={greenBullet}>[ESC]</span>
          <span fg={dimText}> Back to pipeline</span>
        </text>
      </box>
    </box>
  );
}

interface FindingsViewProps {
  findings: StaticFinding[];
  onBack: () => void;
}

function FindingsView({ findings, onBack }: FindingsViewProps) {
  const [selectedIndex, setSelectedIndex] = useState(0);

  // Sort by severity (critical > high > medium > low)
  const sortedFindings = useMemo(() => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return [...findings].sort((a, b) =>
      severityOrder[a.severity] - severityOrder[b.severity]
    );
  }, [findings]);

  useKeyboard((key) => {
    if (key.name === "up") {
      setSelectedIndex(prev => Math.max(0, prev - 1));
    } else if (key.name === "down") {
      setSelectedIndex(prev => Math.min(sortedFindings.length - 1, prev + 1));
    }
  });

  const selected = sortedFindings[selectedIndex];

  return (
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {/* Header */}
      <box
        width="100%"
        border={["bottom"]}
        borderColor={greenBullet}
        flexDirection="row"
        justifyContent="space-between"
        padding={1}
      >
        <text fg={creamText}>Security Findings ({findings.length})</text>
        <text fg={dimText}>↑/↓ to navigate</text>
      </box>

      <box flexDirection="row" flexGrow={1}>
        {/* Left: Finding list */}
        <scrollbox
          style={{
            rootOptions: { width: 45, borderColor: dimText, border: ["right"] },
            contentOptions: { flexDirection: "column", gap: 0 },
          }}
          stickyScroll={false}
          focused={true}
        >
          {sortedFindings.map((finding, i) => {
            const severityColor = {
              critical: redText,
              high: orangeText,
              medium: yellowText,
              low: dimText,
            }[finding.severity];

            return (
              <box
                key={finding.finding_id}
                padding={1}
                backgroundColor={i === selectedIndex ? darkBg : undefined}
                borderColor={i === selectedIndex ? greenBullet : undefined}
                border={i === selectedIndex ? true : undefined}
              >
                <text fg={i === selectedIndex ? creamText : dimText}>
                  <span fg={severityColor}>[{finding.severity.substring(0, 1).toUpperCase()}]</span>
                  {" "}
                  {finding.title.substring(0, 35)}
                </text>
              </box>
            );
          })}
        </scrollbox>

        {/* Right: Finding detail */}
        {selected && (
          <box flexDirection="column" flexGrow={1} padding={2} gap={1}>
            <text fg={creamText}>{selected.title}</text>
            <text fg={dimText}>ID: {selected.finding_id}</text>
            <text fg={dimText}>CWE: {selected.cwe.join(", ") || "N/A"}</text>
            <text fg={dimText}>Confidence: {Math.round(selected.confidence * 100)}%</text>

            {selected.description && (
              <box flexDirection="column" marginTop={1}>
                <text fg={creamText}>Description:</text>
                <text fg={dimText}>{selected.description}</text>
              </box>
            )}

            <box flexDirection="column" marginTop={1}>
              <text fg={creamText}>Location:</text>
              {selected.repo_refs.map((ref, i) => (
                <text key={i} fg={dimText}>• {ref.path}:{ref.start_line}</text>
              ))}
            </box>

            {selected.recommendation && (
              <box flexDirection="column" marginTop={1}>
                <text fg={creamText}>Recommendation:</text>
                <text fg={dimText}>{selected.recommendation.fix_summary}</text>
              </box>
            )}
          </box>
        )}
      </box>

      {/* Footer */}
      <box
        width="100%"
        flexDirection="row"
        justifyContent="flex-end"
        border={["top"]}
        borderColor={greenBullet}
        padding={1}
      >
        <text>
          <span fg={greenBullet}>[ESC]</span>
          <span fg={dimText}> Back to pipeline</span>
        </text>
      </box>
    </box>
  );
}
