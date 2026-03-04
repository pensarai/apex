import { useState, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import AgentDisplay, { type DisplayMessage } from "../agent-display";
import { SpinnerDots } from "../sprites";
import { useDialog } from "../../context/dialog";
import type { ResumeInfo } from "../../../core/session/loader";
import { useTheme } from "../../theme";

// Re-export DisplayMessage as UIMessage for backwards compatibility
export type UIMessage = DisplayMessage;

// Subagent type (inline to avoid circular deps)
export type Subagent = {
  id: string;
  name: string;
  type: "attack-surface" | "pentest";
  target: string;
  messages: DisplayMessage[];
  createdAt: Date;
  status: "pending" | "completed" | "failed" | "paused" | "canceled";
  resumeInfo?: ResumeInfo;
};

interface SwarmDashboardProps {
  subagents: Subagent[];
  isExecuting: boolean;
  startTime?: Date;
  sessionPath?: string;
  isCompleted?: boolean;
  onBack?: () => void;
  onViewReport?: () => void;
  onKillAgent?: (agentId: string) => void;
  onResumeAgent?: (agentId: string) => void;
  children?: React.ReactNode;
}

export default function SwarmDashboard({
  subagents,
  isExecuting,
  startTime,
  sessionPath,
  isCompleted,
  onBack,
  onViewReport,
  onKillAgent,
  onResumeAgent,
}: SwarmDashboardProps) {
  const { colors } = useTheme();
  const [currentView, setCurrentView] = useState<"overview" | "detail">(
    "overview",
  );
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [focusedIndex, setFocusedIndex] = useState(0);
  const [showDiscoveryLogs, setShowDiscoveryLogs] = useState(false);
  const { stack, externalDialogOpen } = useDialog();

  // Separate discovery and pentest agents
  const discoveryAgent = useMemo(
    () =>
      subagents.find(
        (s) => s.type === "attack-surface" && s.status === "pending",
      ) ||
      subagents.find((s) => s.type === "attack-surface") ||
      null,
    [subagents],
  );
  const pentestAgents = useMemo(
    () => subagents.filter((s) => s.type === "pentest"),
    [subagents],
  );

  // Aggregate endpoints from ALL attack-surface agents (old loaded + new active)
  const allEndpoints = useMemo(() => {
    const endpointSet = new Set<string>();
    const attackSurfaceAgents = subagents.filter(
      (s) => s.type === "attack-surface",
    );
    for (const agent of attackSurfaceAgents) {
      for (const msg of agent.messages) {
        if (msg.role === "assistant" && typeof msg.content === "string") {
          const urlMatches = msg.content.match(/\/[a-zA-Z0-9\/_.-]+/g);
          if (urlMatches) {
            urlMatches.forEach((u) => endpointSet.add(u));
          }
        }
      }
    }
    return Array.from(endpointSet).slice(0, 50);
  }, [subagents]);

  // Computed metrics
  const metrics = useMemo(() => {
    const findingsCount = subagents.reduce((sum, s) => {
      return (
        sum +
        s.messages.filter(
          (m) =>
            m.role === "assistant" &&
            typeof m.content === "string" &&
            (m.content.includes("finding") ||
              m.content.includes("vulnerability")),
        ).length
      );
    }, 0);

    return {
      totalFindings: findingsCount,
      activeAgents: subagents.filter((s) => s.status === "pending").length,
      completedAgents: subagents.filter((s) => s.status === "completed").length,
      canceledAgents: subagents.filter((s) => s.status === "canceled").length,
      totalAgents: pentestAgents.length,
      duration: startTime
        ? Math.floor((Date.now() - startTime.getTime()) / 1000)
        : 0,
    };
  }, [subagents, pentestAgents.length, startTime]);

  // Get currently selected agent for detail view
  const selectedAgent = useMemo(
    () =>
      selectedAgentId ? subagents.find((s) => s.id === selectedAgentId) : null,
    [subagents, selectedAgentId],
  );

  // Keyboard navigation
  useKeyboard((key) => {
    // Skip all keyboard handling when any dialog is open
    if (stack.length > 0 || externalDialogOpen) return;

    if (currentView === "overview") {
      // D to toggle discovery logs
      if (key.name === "d" || key.name === "D") {
        setShowDiscoveryLogs((prev) => !prev);
        return;
      }

      // R to resume paused discovery agent
      if (
        (key.name === "r" || key.name === "R") &&
        discoveryAgent?.status === "paused"
      ) {
        onResumeAgent?.(discoveryAgent.id);
        return;
      }

      const agentCount = pentestAgents.length;

      // ESC to exit when no agents or close discovery logs first
      if (key.name === "escape") {
        if (showDiscoveryLogs) {
          setShowDiscoveryLogs(false);
          return;
        }
        onBack?.();
        return;
      }

      if (agentCount === 0) {
        return;
      }

      // Tab/Arrow navigation between cards
      if (key.name === "tab" && !key.shift) {
        setFocusedIndex((prev) => (prev + 1) % agentCount);
        return;
      }
      if ((key.name === "tab" && key.shift) || key.name === "left") {
        setFocusedIndex((prev) => (prev - 1 + agentCount) % agentCount);
        return;
      }
      if (key.name === "right") {
        setFocusedIndex((prev) => (prev + 1) % agentCount);
        return;
      }
      if (key.name === "down") {
        // Move down 2 (2-column grid)
        setFocusedIndex((prev) => Math.min(prev + 2, agentCount - 1));
        return;
      }
      if (key.name === "up") {
        // Move up 2 (2-column grid)
        setFocusedIndex((prev) => Math.max(prev - 2, 0));
        return;
      }

      // Kill focused agent with X or Delete
      if (
        (key.name === "x" || key.name === "X" || key.name === "delete") &&
        pentestAgents[focusedIndex]
      ) {
        const focusedAgent = pentestAgents[focusedIndex]!;
        if (focusedAgent.status === "pending") {
          onKillAgent?.(focusedAgent.id);
        }
        return;
      }

      // Enter to drill into agent
      if (key.name === "return") {
        if (pentestAgents[focusedIndex]) {
          setSelectedAgentId(pentestAgents[focusedIndex]!.id);
          setCurrentView("detail");
        } else if (isCompleted && onViewReport) {
          onViewReport();
        }
        return;
      }
    } else if (currentView === "detail") {
      // ESC to return to overview
      if (key.name === "escape") {
        setCurrentView("overview");
        setSelectedAgentId(null);
        return;
      }
      // R to resume paused agent
      if (
        (key.name === "r" || key.name === "R") &&
        selectedAgent?.status === "paused"
      ) {
        onResumeAgent?.(selectedAgent.id);
        return;
      }
    }
  });

  // Agent detail view
  if (currentView === "detail" && selectedAgent) {
    return (
      <AgentDetailView
        agent={selectedAgent}
        onBack={() => {
          setCurrentView("overview");
          setSelectedAgentId(null);
        }}
        onResume={
          selectedAgent.status === "paused"
            ? () => onResumeAgent?.(selectedAgent.id)
            : undefined
        }
      />
    );
  }

  // Overview view
  return (
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {/* Main content area */}
      <box flexDirection="row" flexGrow={1} gap={2} padding={1}>
        {/* Left: Discovery panel */}
        <DiscoveryPanel
          agent={discoveryAgent}
          endpoints={allEndpoints}
          showLogs={showDiscoveryLogs}
          onToggleLogs={() => setShowDiscoveryLogs((prev) => !prev)}
        />

        {/* Right: Agent card grid */}
        <box flexDirection="column" flexGrow={1} gap={1}>
          {pentestAgents.length === 0 ? (
            <box
              flexGrow={1}
              alignItems="center"
              justifyContent="center"
              border
              borderColor={colors.textMuted}
              backgroundColor={colors.background}
              padding={2}
            >
              {discoveryAgent?.status === "paused" ? (
                <box flexDirection="column" alignItems="center" gap={1}>
                  <text fg={colors.tierRisky}>⏸ Discovery was interrupted</text>
                  <text fg={colors.textMuted}>
                    Press <span fg={colors.tierRisky}>[R]</span> to resume
                  </text>
                </box>
              ) : discoveryAgent?.status === "pending" ? (
                <box flexDirection="column" alignItems="center" gap={1}>
                  <SpinnerDots
                    label="Discovering attack surface..."
                    fg={colors.primary}
                  />
                  <text fg={colors.textMuted}>
                    Press [D] to view discovery logs
                  </text>
                </box>
              ) : (
                <text fg={colors.textMuted}>No pentest agents spawned yet</text>
              )}
            </box>
          ) : (
            <AgentCardGrid
              agents={pentestAgents}
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
      {isCompleted && (
        <box
          width="100%"
          padding={1}
          backgroundColor={colors.background}
          border
          borderColor={colors.primary}
          flexDirection="column"
          alignItems="center"
          gap={1}
        >
          <text fg={colors.primary}>Pentest Completed</text>
          <text fg={colors.textMuted}>{sessionPath}/pentest-report.md</text>
          <box flexDirection="row" gap={2}>
            <text>
              <span fg={colors.primary}>[Enter]</span>
              <span fg={colors.textMuted}> View Report</span>
            </text>
            <text>
              <span fg={colors.primary}>[ESC]</span>
              <span fg={colors.textMuted}> Close</span>
            </text>
          </box>
        </box>
      )}

      {/* Bottom: Metrics bar */}
      <MetricsBar
        totalFindings={metrics.totalFindings}
        activeAgents={metrics.activeAgents}
        totalAgents={metrics.totalAgents}
        canceledAgents={metrics.canceledAgents}
        duration={metrics.duration}
        isExecuting={isExecuting}
        showKillHint={!!onKillAgent}
        discoveryPaused={discoveryAgent?.status === "paused"}
      />
    </box>
  );
}

// ============================================================================
// Sub-components (inline for simplicity)
// ============================================================================

interface DiscoveryPanelProps {
  agent: Subagent | null;
  endpoints: string[];
  showLogs: boolean;
  onToggleLogs: () => void;
}

function DiscoveryPanel({
  agent,
  endpoints,
  showLogs,
  onToggleLogs,
}: DiscoveryPanelProps) {
  const { colors } = useTheme();
  // Expanded logs view
  if (showLogs && agent) {
    return (
      <box
        flexGrow={1}
        border
        borderColor={colors.primary}
        backgroundColor={colors.background}
        flexDirection="column"
      >
        {/* Header */}
        <box
          flexDirection="row"
          alignItems="center"
          justifyContent="space-between"
          padding={1}
          borderColor={colors.textMuted}
          border={["bottom"]}
        >
          <box flexDirection="row" gap={1}>
            {agent.status === "pending" && (
              <SpinnerDots
                label="Attack Surface Discovery"
                fg={colors.primary}
              />
            )}
            {agent.status === "completed" && (
              <text fg={colors.primary}>✓ Attack Surface Discovery</text>
            )}
            {agent.status === "failed" && (
              <text fg={colors.error}>✗ Attack Surface Discovery</text>
            )}
            {agent.status === "paused" && (
              <text fg={colors.tierRisky}>
                ⏸ Attack Surface Discovery (Paused)
              </text>
            )}
          </box>
          <text fg={colors.textMuted}>
            <span fg={colors.primary}>[D]</span> to collapse |{" "}
            <span fg={colors.primary}>[ESC]</span> to close
          </text>
        </box>

        {/* Full message log */}
        <AgentDisplay
          messages={agent.messages}
          isStreaming={agent.status === "pending"}
          focused={true}
          paddingLeft={2}
          paddingRight={2}
          contextId="discovery-logs"
        />

        {/* Footer stats */}
        <box
          flexDirection="row"
          justifyContent="space-between"
          padding={1}
          borderColor={colors.textMuted}
          border={["top"]}
        >
          <text fg={colors.textMuted}>{agent.messages.length} messages</text>
          <text fg={colors.textMuted}>{endpoints.length} endpoints found</text>
        </box>
      </box>
    );
  }

  // Collapsed panel view
  return (
    <box
      width={32}
      border
      borderColor={
        agent?.status === "pending" ? colors.primary : colors.textMuted
      }
      backgroundColor={colors.background}
      flexDirection="column"
      onMouseDown={onToggleLogs}
    >
      {/* Header */}
      <box
        flexDirection="row"
        alignItems="center"
        justifyContent="space-between"
        padding={1}
        borderColor={colors.textMuted}
        border={["bottom"]}
      >
        <box flexDirection="row" gap={1}>
          {!agent && <text fg={colors.textMuted}>Waiting...</text>}
          {agent?.status === "pending" && (
            <SpinnerDots label="Discovery" fg={colors.primary} />
          )}
          {agent?.status === "completed" && (
            <text fg={colors.primary}>✓ Discovery</text>
          )}
          {agent?.status === "failed" && (
            <text fg={colors.error}>✗ Discovery</text>
          )}
          {agent?.status === "paused" && (
            <text fg={colors.tierRisky}>⏸ Discovery</text>
          )}
        </box>
        <text fg={colors.textMuted}>[D]</text>
      </box>

      {/* Stats */}
      {agent && (
        <box flexDirection="column" padding={1} gap={1}>
          <text>
            <span fg={colors.textMuted}>Status: </span>
            <span
              fg={
                agent.status === "pending"
                  ? colors.primary
                  : agent.status === "paused"
                    ? colors.tierRisky
                    : colors.text
              }
            >
              {agent.status}
            </span>
          </text>
          <text>
            <span fg={colors.textMuted}>Messages: </span>
            <span fg={colors.text}>{agent.messages.length}</span>
          </text>
          <text>
            <span fg={colors.textMuted}>Endpoints: </span>
            <span fg={colors.text}>{endpoints.length}</span>
          </text>
          {agent.status === "paused" && (
            <text>
              <span fg={colors.tierRisky}>[R]</span>
              <span fg={colors.textMuted}> Resume</span>
            </text>
          )}
        </box>
      )}

      {/* Scrollable endpoint list */}
      {endpoints.length > 0 && (
        <scrollbox
          style={{
            rootOptions: { flexGrow: 1, paddingLeft: 1, paddingRight: 1 },
            contentOptions: { flexDirection: "column", gap: 0 },
          }}
          stickyScroll={false}
          focused={false}
        >
          <text fg={colors.textMuted}>Endpoints:</text>
          {endpoints.map((endpoint, i) => (
            <text key={i} fg={colors.textMuted}>
              <span fg={colors.primary}>• </span>
              {endpoint.length > 26 ? endpoint.slice(0, 26) + "…" : endpoint}
            </text>
          ))}
        </scrollbox>
      )}
    </box>
  );
}

interface AgentCardProps {
  agent: Subagent;
  focused: boolean;
  onSelect: () => void;
}

function AgentCard({ agent, focused, onSelect }: AgentCardProps) {
  const { colors } = useTheme();
  const statusIcon = {
    pending: "◐",
    completed: "✓",
    failed: "✗",
    paused: "⏸",
    canceled: "⊘",
  }[agent.status];

  const statusColor = {
    pending: colors.primary,
    completed: colors.primary,
    failed: colors.error,
    paused: colors.tierRisky,
    canceled: colors.textMuted,
  }[agent.status];

  // Get brief activity from last message (truncated to single line)
  const lastActivity = useMemo(() => {
    const lastMsg = agent.messages[agent.messages.length - 1];
    if (!lastMsg) return "Starting...";
    let text = "";
    if (lastMsg.role === "tool" && typeof lastMsg.content === "string") {
      text = lastMsg.content.replace(/\n/g, " ").trim();
    } else if (typeof lastMsg.content === "string") {
      text = lastMsg.content.replace(/\n/g, " ").trim();
    } else {
      return "Working...";
    }
    // Truncate to ~50 chars to fit on one line
    if (text.length > 50) {
      return text.substring(0, 47) + "...";
    }
    return text;
  }, [agent.messages]);

  // Count tool calls and findings
  const stats = useMemo(() => {
    const toolCalls = agent.messages.filter((m) => m.role === "tool").length;
    return { toolCalls };
  }, [agent.messages]);

  return (
    <box
      flexGrow={1}
      flexBasis={0}
      minWidth={40}
      border
      borderColor={focused ? colors.primary : colors.textMuted}
      backgroundColor={colors.background}
      flexDirection="column"
      padding={1}
      rowGap={1}
      onMouseDown={onSelect}
    >
      {/* Header row */}
      <box flexDirection="row" alignItems="center" gap={1} flexWrap="wrap">
        <text fg={statusColor}>{statusIcon}</text>
        <text fg={focused ? colors.text : colors.textMuted}>{agent.name}</text>
      </box>

      {/* Target - allow wrapping */}
      <text fg={colors.textMuted}>{agent.target}</text>

      {/* Stats row */}
      <box flexDirection="row" gap={2} marginTop={1}>
        <text fg={colors.textMuted}>
          <span fg={colors.primary}>{stats.toolCalls}</span> calls
        </text>
        <text fg={colors.textMuted}>
          <span fg={colors.primary}>{agent.messages.length}</span> msgs
        </text>
      </box>

      {/* Activity / Status - single line */}
      <box height={1} overflow="hidden">
        {agent.status === "canceled" ? (
          <text fg={colors.textMuted}>⊘ Canceled</text>
        ) : agent.status === "pending" ? (
          <SpinnerDots label={lastActivity} fg={colors.primary} />
        ) : agent.status === "paused" ? (
          <text fg={colors.tierRisky}>
            ⏸ Paused — press Enter then R to resume
          </text>
        ) : (
          <text
            fg={
              agent.status === "completed" ? colors.primary : colors.textMuted
            }
          >
            {agent.status === "completed" ? "✓ Complete" : lastActivity}
          </text>
        )}
      </box>
    </box>
  );
}

interface AgentCardGridProps {
  agents: Subagent[];
  focusedIndex: number;
  onSelectAgent: (agentId: string) => void;
}

function AgentCardGrid({
  agents,
  focusedIndex,
  onSelectAgent,
}: AgentCardGridProps) {
  // Organize into rows of 2
  const rows = useMemo(() => {
    const result: Subagent[][] = [];
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
              <AgentCard
                key={agent.id}
                agent={agent}
                focused={flatIndex === focusedIndex}
                onSelect={() => onSelectAgent(agent.id)}
              />
            );
          })}
          {/* Add empty spacer if odd number of agents in last row */}
          {row.length === 1 && <box flexGrow={1} flexBasis={0} minWidth={40} />}
        </box>
      ))}
    </scrollbox>
  );
}

interface MetricsBarProps {
  totalFindings: number;
  activeAgents: number;
  totalAgents: number;
  canceledAgents: number;
  duration: number;
  isExecuting: boolean;
  showKillHint?: boolean;
  discoveryPaused?: boolean;
}

function MetricsBar({
  totalFindings,
  activeAgents,
  totalAgents,
  canceledAgents,
  duration,
  isExecuting,
  showKillHint,
  discoveryPaused,
}: MetricsBarProps) {
  const { colors } = useTheme();
  // Format duration as mm:ss
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
      borderColor={colors.primary}
      border={["top"]}
      padding={1}
    >
      {/* Left: Metrics */}
      <box flexDirection="row" gap={2}>
        <text>
          <span fg={colors.primary}>{totalFindings}</span>
          <span fg={colors.textMuted}> findings</span>
        </text>
        <text fg={colors.textMuted}>|</text>
        <text>
          <span fg={isExecuting ? colors.primary : colors.textMuted}>
            {activeAgents}
          </span>
          <span fg={colors.textMuted}>/{totalAgents} active</span>
        </text>
        {canceledAgents > 0 && (
          <>
            <text fg={colors.textMuted}>|</text>
            <text>
              <span fg={colors.textMuted}>{canceledAgents}</span>
              <span fg={colors.textMuted}> canceled</span>
            </text>
          </>
        )}
        <text fg={colors.textMuted}>|</text>
        <text fg={colors.textMuted}>{formattedDuration}</text>
      </box>

      {/* Right: Keyboard hints */}
      <box flexDirection="row" gap={2}>
        {discoveryPaused && (
          <text>
            <span fg={colors.tierRisky}>[R]</span>
            <span fg={colors.textMuted}> Resume</span>
          </text>
        )}
        {showKillHint && (
          <text>
            <span fg={colors.primary}>[X]</span>
            <span fg={colors.textMuted}> Kill</span>
          </text>
        )}
        <text>
          <span fg={colors.primary}>[D]</span>
          <span fg={colors.textMuted}> Discovery</span>
        </text>
        <text>
          <span fg={colors.primary}>[Tab]</span>
          <span fg={colors.textMuted}> Navigate</span>
        </text>
        <text>
          <span fg={colors.primary}>[Enter]</span>
          <span fg={colors.textMuted}> View</span>
        </text>
        <text>
          <span fg={colors.primary}>[ESC]</span>
          <span fg={colors.textMuted}> Back</span>
        </text>
      </box>
    </box>
  );
}

interface AgentDetailViewProps {
  agent: Subagent;
  onBack: () => void;
  onResume?: () => void;
}

function AgentDetailView({ agent, onBack, onResume }: AgentDetailViewProps) {
  const { colors } = useTheme();
  const statusColor = {
    pending: colors.primary,
    completed: colors.primary,
    failed: colors.error,
    paused: colors.tierRisky,
    canceled: colors.textMuted,
  }[agent.status];

  return (
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {/* Header */}
      <box
        width="100%"
        border={["bottom"]}
        borderColor={colors.primary}
        flexDirection="row"
        justifyContent="space-between"
        padding={1}
      >
        <box flexDirection="row" gap={1}>
          <text fg={colors.textMuted}></text>
          <text fg={colors.text}>{agent.name}</text>
        </box>
        <box flexDirection="row" gap={2}>
          <text>
            <span fg={colors.textMuted}>Target: </span>
            <span fg={colors.text}>{agent.target}</span>
          </text>
          <text fg={statusColor}>{agent.status}</text>
        </box>
      </box>

      {/* Message content - reuse existing AgentDisplay */}
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
        borderColor={colors.primary}
        padding={1}
      >
        <text>
          <span fg={colors.textMuted}>{agent.messages.length} messages</span>
        </text>
        <box flexDirection="row" gap={2}>
          {agent.status === "paused" && onResume && (
            <text>
              <span fg={colors.tierRisky}>[R]</span>
              <span fg={colors.textMuted}> Resume</span>
            </text>
          )}
          <text>
            <span fg={colors.primary}>[ESC]</span>
            <span fg={colors.textMuted}> Back to swarm</span>
          </text>
          <text>
            <span fg={colors.primary}>[/]</span>
            <span fg={colors.textMuted}> Scroll</span>
          </text>
        </box>
      </box>
    </box>
  );
}
