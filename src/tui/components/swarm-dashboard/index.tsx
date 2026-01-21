import { useState, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import AgentDisplay, { type DisplayMessage } from "../agent-display";
import { SpinnerDots } from "../sprites";
import { useDialog } from "../../context/dialog";

// Color palette (matching home view)
export const greenBullet = RGBA.fromInts(76, 175, 80, 255);
export const creamText = RGBA.fromInts(255, 248, 220, 255);
export const dimText = RGBA.fromInts(120, 120, 120, 255);
export const darkBg = RGBA.fromInts(10, 10, 10, 255);

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
  status: "pending" | "completed" | "failed";
};

interface SwarmDashboardProps {
  subagents: Subagent[];
  isExecuting: boolean;
  startTime?: Date;
  sessionPath?: string;
  isCompleted?: boolean;
  onBack?: () => void;
  onViewReport?: () => void;
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
}: SwarmDashboardProps) {
  const [currentView, setCurrentView] = useState<"overview" | "detail">(
    "overview"
  );
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [focusedIndex, setFocusedIndex] = useState(0);
  const [showDiscoveryLogs, setShowDiscoveryLogs] = useState(false);
  const { stack, externalDialogOpen } = useDialog();

  // Separate discovery and pentest agents
  const discoveryAgent = useMemo(
    () => subagents.find((s) => s.type === "attack-surface") || null,
    [subagents]
  );
  const pentestAgents = useMemo(
    () => subagents.filter((s) => s.type === "pentest"),
    [subagents]
  );

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
              m.content.includes("vulnerability"))
        ).length
      );
    }, 0);

    return {
      totalFindings: findingsCount,
      activeAgents: subagents.filter((s) => s.status === "pending").length,
      completedAgents: subagents.filter((s) => s.status === "completed").length,
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
    [subagents, selectedAgentId]
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
              borderColor={dimText}
              backgroundColor={darkBg}
              padding={2}
            >
              {discoveryAgent?.status === "pending" ? (
                <box flexDirection="column" alignItems="center" gap={1}>
                  <SpinnerDots
                    label="Discovering attack surface..."
                    fg="green"
                  />
                  <text fg={dimText}>Press [D] to view discovery logs</text>
                </box>
              ) : (
                <text fg={dimText}>No pentest agents spawned yet</text>
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
          backgroundColor={darkBg}
          border
          borderColor={greenBullet}
          flexDirection="column"
          alignItems="center"
          gap={1}
        >
          <text fg={greenBullet}>Pentest Completed</text>
          <text fg={dimText}>
            {sessionPath}/comprehensive-pentest-report.md
          </text>
          <box flexDirection="row" gap={2}>
            <text>
              <span fg={greenBullet}>[Enter]</span>
              <span fg={dimText}> View Report</span>
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
        activeAgents={metrics.activeAgents}
        totalAgents={metrics.totalAgents}
        duration={metrics.duration}
        isExecuting={isExecuting}
      />
    </box>
  );
}

// ============================================================================
// Sub-components (inline for simplicity)
// ============================================================================

interface DiscoveryPanelProps {
  agent: Subagent | null;
  showLogs: boolean;
  onToggleLogs: () => void;
}

function DiscoveryPanel({
  agent,
  showLogs,
  onToggleLogs,
}: DiscoveryPanelProps) {
  // Extract endpoints from agent messages
  const endpoints = useMemo(() => {
    if (!agent) return [];
    const endpointSet = new Set<string>();

    for (const msg of agent.messages) {
      if (msg.role === "assistant" && typeof msg.content === "string") {
        // Look for URL patterns
        const urlMatches = msg.content.match(/\/[a-zA-Z0-9\/_-]+/g);
        if (urlMatches) {
          urlMatches.forEach((u) => endpointSet.add(u));
        }
      }
    }
    return Array.from(endpointSet).slice(0, 50);
  }, [agent?.messages]);

  // Expanded logs view
  if (showLogs && agent) {
    return (
      <box
        flexGrow={1}
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
          <box flexDirection="row" gap={1}>
            {agent.status === "pending" && (
              <SpinnerDots label="Attack Surface Discovery" fg="green" />
            )}
            {agent.status === "completed" && (
              <text fg={greenBullet}>✓ Attack Surface Discovery</text>
            )}
            {agent.status === "failed" && (
              <text fg="red">✗ Attack Surface Discovery</text>
            )}
          </box>
          <text fg={dimText}>
            <span fg={greenBullet}>[D]</span> to collapse |{" "}
            <span fg={greenBullet}>[ESC]</span> to close
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
          borderColor={dimText}
          border={["top"]}
        >
          <text fg={dimText}>{agent.messages.length} messages</text>
          <text fg={dimText}>{endpoints.length} endpoints found</text>
        </box>
      </box>
    );
  }

  // Collapsed panel view
  return (
    <box
      width={32}
      border
      borderColor={agent?.status === "pending" ? greenBullet : dimText}
      backgroundColor={darkBg}
      flexDirection="column"
      onMouseDown={onToggleLogs}
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
        <box flexDirection="row" gap={1}>
          {!agent && <text fg={dimText}>Waiting...</text>}
          {agent?.status === "pending" && (
            <SpinnerDots label="Discovery" fg="green" />
          )}
          {agent?.status === "completed" && (
            <text fg={greenBullet}>✓ Discovery</text>
          )}
          {agent?.status === "failed" && <text fg="red">✗ Discovery</text>}
        </box>
        <text fg={dimText}>[D]</text>
      </box>

      {/* Stats */}
      {agent && (
        <box flexDirection="column" padding={1} gap={1}>
          <text>
            <span fg={dimText}>Status: </span>
            <span fg={agent.status === "pending" ? greenBullet : creamText}>
              {agent.status}
            </span>
          </text>
          <text>
            <span fg={dimText}>Messages: </span>
            <span fg={creamText}>{agent.messages.length}</span>
          </text>
          <text>
            <span fg={dimText}>Endpoints: </span>
            <span fg={creamText}>{endpoints.length}</span>
          </text>
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
          <text fg={dimText}>Endpoints:</text>
          {endpoints.map((endpoint, i) => (
            <text key={i} fg={dimText}>
              <span fg={greenBullet}>• </span>
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
  const statusIcon = {
    pending: "◐",
    completed: "✓",
    failed: "✗",
  }[agent.status];

  const statusColor = {
    pending: greenBullet,
    completed: greenBullet,
    failed: RGBA.fromInts(244, 67, 54, 255),
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
      borderColor={focused ? greenBullet : dimText}
      backgroundColor={darkBg}
      flexDirection="column"
      padding={1}
      rowGap={1}
      onMouseDown={onSelect}
    >
      {/* Header row */}
      <box flexDirection="row" alignItems="center" gap={1} flexWrap="wrap">
        <text fg={statusColor}>{statusIcon}</text>
        <text fg={focused ? creamText : dimText}>{agent.name}</text>
      </box>

      {/* Target - allow wrapping */}
      <text fg={dimText}>{agent.target}</text>

      {/* Stats row */}
      <box flexDirection="row" gap={2} marginTop={1}>
        <text fg={dimText}>
          <span fg={greenBullet}>{stats.toolCalls}</span> calls
        </text>
        <text fg={dimText}>
          <span fg={greenBullet}>{agent.messages.length}</span> msgs
        </text>
      </box>

      {/* Activity / Status - single line */}
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
  duration: number;
  isExecuting: boolean;
}

function MetricsBar({
  totalFindings,
  activeAgents,
  totalAgents,
  duration,
  isExecuting,
}: MetricsBarProps) {
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
      borderColor={greenBullet}
      border={["top"]}
      padding={1}
    >
      {/* Left: Metrics */}
      <box flexDirection="row" gap={2}>
        <text>
          <span fg={greenBullet}>{totalFindings}</span>
          <span fg={dimText}> findings</span>
        </text>
        <text fg={dimText}>|</text>
        <text>
          <span fg={isExecuting ? greenBullet : dimText}>{activeAgents}</span>
          <span fg={dimText}>/{totalAgents} active</span>
        </text>
        <text fg={dimText}>|</text>
        <text fg={dimText}>{formattedDuration}</text>
      </box>

      {/* Right: Keyboard hints */}
      <box flexDirection="row" gap={2}>
        <text>
          <span fg={greenBullet}>[D]</span>
          <span fg={dimText}> Discovery</span>
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
  agent: Subagent;
  onBack: () => void;
}

function AgentDetailView({ agent, onBack }: AgentDetailViewProps) {
  const statusColor = {
    pending: greenBullet,
    completed: greenBullet,
    failed: RGBA.fromInts(244, 67, 54, 255),
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
          <text fg={dimText}></text>
          <text fg={creamText}>{agent.name}</text>
        </box>
        <box flexDirection="row" gap={2}>
          <text>
            <span fg={dimText}>Target: </span>
            <span fg={creamText}>{agent.target}</span>
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
        borderColor={greenBullet}
        padding={1}
      >
        <text>
          <span fg={dimText}>{agent.messages.length} messages</span>
        </text>
        <box flexDirection="row" gap={2}>
          <text>
            <span fg={greenBullet}>[ESC]</span>
            <span fg={dimText}> Back to swarm</span>
          </text>
          <text>
            <span fg={greenBullet}>[/]</span>
            <span fg={dimText}> Scroll</span>
          </text>
        </box>
      </box>
    </box>
  );
}
