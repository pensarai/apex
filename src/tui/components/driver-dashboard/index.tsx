/**
 * Driver Dashboard
 *
 * Main dashboard for driver mode - allows users to manually orchestrate agents.
 * Features:
 * - Agent grid showing running/completed agents
 * - Endpoint sidebar showing recon discoveries
 * - Keyboard navigation and agent spawning
 */

import { useState, useEffect, useMemo, useCallback } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { Session } from "../../../core/session";
import type { PentestTarget, AttackSurfaceAnalysisResults } from "../../../core/agent/attackSurfaceAgent/types";
import { runAgent as runAttackSurfaceAgent } from "../../../core/agent/attackSurfaceAgent";
import { createDriverModeAgent, type DriverModeAgent } from "../../../core/agent/driverModeAgent";
import { extractPentestTarget, type DiscoveredEndpoint } from "../../../core/agent/driverModeAgent/targetExtractor";
import type { DisplayMessage } from "../agent-display";
import AgentDisplay from "../agent-display";
import { SpinnerDots } from "../sprites";
import { useRoute } from "../../context/route";
import { useAgent } from "../../agentProvider";
import { useDialog } from "../dialog";
import EndpointSidebar from "./endpoint-sidebar";
import AgentChatView from "./agent-chat-view";
import MentionAutocomplete from "./mention-autocomplete";

// Color palette
const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const darkBg = RGBA.fromInts(10, 10, 10, 255);

/**
 * Agent state in the driver dashboard
 */
interface DriverAgent {
  id: string;
  name: string;
  target: PentestTarget;
  status: 'running' | 'paused' | 'completed' | 'failed';
  messages: DisplayMessage[];
  createdAt: Date;
  agentRef: DriverModeAgent;
}

interface DriverDashboardProps {
  session: Session.SessionInfo;
}

export default function DriverDashboard({ session }: DriverDashboardProps) {
  const route = useRoute();
  const { model } = useAgent();
  const { stack, externalDialogOpen } = useDialog();

  // State
  const [currentView, setCurrentView] = useState<'overview' | 'agent-chat' | 'recon-view'>('overview');
  const [agents, setAgents] = useState<DriverAgent[]>([]);
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [reconStatus, setReconStatus] = useState<'idle' | 'running' | 'completed'>('idle');
  const [reconMessages, setReconMessages] = useState<DisplayMessage[]>([]);
  const [focusedArea, setFocusedArea] = useState<'agents' | 'endpoints'>('agents');
  const [focusedAgentIndex, setFocusedAgentIndex] = useState(0);
  const [focusedEndpointIndex, setFocusedEndpointIndex] = useState(0);
  const [activeAgentId, setActiveAgentId] = useState<string | null>(null);
  const [showNewAgentInput, setShowNewAgentInput] = useState(false);
  const [newAgentInput, setNewAgentInput] = useState('');
  const [startTime] = useState(() => new Date());
  const [showMentions, setShowMentions] = useState(false);
  const [mentionQuery, setMentionQuery] = useState('');

  const [loading, setLoading] = useState(false);

  // Get active agent
  const activeAgent = useMemo(
    () => agents.find(a => a.id === activeAgentId) || null,
    [agents, activeAgentId]
  );

  // Auto-start recon on mount
  useEffect(() => {
    if (reconStatus === 'idle') {
      startRecon();
    }
  }, []);

    // Handle input changes
  const handleInput = useCallback((value: string) => {
    if(loading) {
      return;
    }
    setNewAgentInput(value);

    // Check for @ mention trigger
    const lastAtIndex = value.lastIndexOf('@');
    if (lastAtIndex !== -1 && lastAtIndex === value.length - 1) {
      // Just typed @
      setShowMentions(true);
      setMentionQuery('');
    } else if (lastAtIndex !== -1) {
      // Typing after @
      const afterAt = value.substring(lastAtIndex + 1);
      if (!afterAt.includes(' ')) {
        setShowMentions(true);
        setMentionQuery(afterAt);
      } else {
        setShowMentions(false);
      }
    } else {
      setShowMentions(false);
    }
  }, []);

    // Handle mention selection - insert the actual URL
  const handleMentionSelect = useCallback((endpoint: DiscoveredEndpoint) => {
    const lastAtIndex = newAgentInput.lastIndexOf('@');
    const newValue = newAgentInput.substring(0, lastAtIndex) + endpoint.url + ' ';
    setNewAgentInput(newValue);
    setShowMentions(false);
  }, [newAgentInput]);

  // Start recon agent
  const startRecon = useCallback(async () => {
    setReconStatus('running');
    setReconMessages([{
      role: 'user',
      content: `Starting attack surface discovery for: ${session.targets[0]}`,
      createdAt: new Date(),
    }]);

    try {
      const { streamResult } = await runAttackSurfaceAgent({
        target: session.targets[0] || '',
        objective: 'Comprehensive attack surface discovery and target identification',
        model: model.id,
        session,
        onStepFinish: async (step) => {
          const { text, toolCalls, toolResults } = step;

          setReconMessages(prev => {
            const newMessages = [...prev];

            // Add text content
            if (text && text.trim()) {
              const lastMsg = newMessages[newMessages.length - 1];
              if (lastMsg && lastMsg.role === 'assistant') {
                newMessages[newMessages.length - 1] = {
                  ...lastMsg,
                  content: (lastMsg.content || '') + text,
                };
              } else {
                newMessages.push({
                  role: 'assistant',
                  content: text,
                  createdAt: new Date(),
                });
              }
            }

            // Add tool calls
            if (toolCalls && toolCalls.length > 0) {
              for (const tc of toolCalls) {
                const args = (tc as any).input as Record<string, unknown> | undefined;
                const toolDescription =
                  typeof args?.toolCallDescription === 'string'
                    ? args.toolCallDescription
                    : tc.toolName;
                newMessages.push({
                  role: 'tool',
                  status: 'pending',
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
              for (const tr of toolResults) {
                const msgIdx = newMessages.findIndex(
                  (m) => m.role === 'tool' && (m as any).toolCallId === tr.toolCallId
                );
                if (msgIdx !== -1) {
                  const existingMsg = newMessages[msgIdx] as DisplayMessage & { toolName?: string; toolCallId?: string };
                  const description =
                    typeof existingMsg.content === 'string' &&
                    existingMsg.content !== existingMsg.toolName
                      ? existingMsg.content
                      : existingMsg.toolName || 'tool';
                  newMessages[msgIdx] = {
                    ...existingMsg,
                    status: 'completed',
                    content: `✓ ${description}`,
                    result: (tr as any).output,
                  };
                }
              }
            }

            return newMessages;
          });
        },
      });

      // Consume the stream to let the agent complete
      for await (const _chunk of streamResult.fullStream) {
        // Just consume - messages are captured via onStepFinish
      }

      // Read results from the JSON file created by the agent
      const resultsPath = join(session.rootPath, 'attack-surface-results.json');

      if (!existsSync(resultsPath)) {
        console.log('No attack surface results file found');
        setReconStatus('completed');
        return;
      }

      const resultsData = readFileSync(resultsPath, 'utf-8');
      const results: AttackSurfaceAnalysisResults = JSON.parse(resultsData);

      // Convert results to discovered endpoints
      const discoveredEndpoints: DiscoveredEndpoint[] = (results.targets || []).map((t: PentestTarget, i: number) => ({
        id: `endpoint-${i}`,
        url: t.target,
        method: 'GET',
        suggestedObjective: t.objective,
        source: 'recon' as const,
      }));

      setEndpoints(discoveredEndpoints);
      setReconStatus('completed');
    } catch (error) {
      console.error('Recon failed:', error);
      setReconStatus('completed');
    }
  }, [session, model.id]);

  // Spawn agent from target
  const spawnAgent = useCallback(async (target: PentestTarget) => {
    const agentId = `agent-${Date.now()}`;
    const agentName = `Agent ${agents.length + 1}`;

    const driverAgent = createDriverModeAgent({
      session,
      model: model.id,
      vulnerabilityClass: 'generic',
    });

    const newAgent: DriverAgent = {
      id: agentId,
      name: agentName,
      target,
      status: 'running',
      messages: [],
      createdAt: new Date(),
      agentRef: driverAgent,
    };

    // Set up event listeners
    driverAgent.on('message', (message: DisplayMessage) => {
      setAgents(prev => prev.map(a =>
        a.id === agentId
          ? { ...a, messages: [...a.messages, message] }
          : a
      ));
    });

    driverAgent.on('status-change', (status: string) => {
      setAgents(prev => prev.map(a =>
        a.id === agentId
          ? { ...a, status: status as DriverAgent['status'] }
          : a
      ));
    });

    driverAgent.on('complete', () => {
      setAgents(prev => prev.map(a =>
        a.id === agentId
          ? { ...a, status: 'completed' }
          : a
      ));
    });

    driverAgent.on('error', () => {
      setAgents(prev => prev.map(a =>
        a.id === agentId
          ? { ...a, status: 'failed' }
          : a
      ));
    });

    setAgents(prev => [...prev, newAgent]);
    setActiveAgentId(agentId);
    setCurrentView('agent-chat');

    // Start the agent
    driverAgent.start(target).catch(console.error);
  }, [agents.length, session, model.id]);

  // Spawn agent from endpoint
  const spawnAgentFromEndpoint = useCallback(async (endpoint: DiscoveredEndpoint) => {
    const target: PentestTarget = {
      target: endpoint.url,
      objective: endpoint.suggestedObjective,
      rationale: 'Spawned from discovered endpoint',
    };

    await spawnAgent(target);
  }, [spawnAgent]);

  // Handle new agent creation from input
  const handleCreateNewAgent = useCallback(async () => {
    if (!newAgentInput.trim()) {
      setShowNewAgentInput(false);
      return;
    }

    if(loading) {
      return;
    }

    setLoading(true);

    try {
      const target = await extractPentestTarget({
        userMessage: newAgentInput,
        discoveredEndpoints: endpoints,
        model: model.id,
      });

      await spawnAgent(target);
      setNewAgentInput('');
      setShowNewAgentInput(false);
    } catch (error) {
      console.error('Failed to extract target:', error);
      // TODO: error toast
    }
    setLoading(false);
  }, [newAgentInput, endpoints, model.id, spawnAgent]);

  // Keyboard navigation
  useKeyboard((key) => {
    // Skip all keyboard handling when any dialog is open
    if (stack.length > 0 || externalDialogOpen) return;

    // Handle agent chat view separately
    if (currentView === 'agent-chat') {
      // Shift+/ to return to dashboard
      if (key.shift && key.name === '/') {
        setCurrentView('overview');
        return;
      }
      return; // Let AgentChatView handle other keys
    }

    // Handle recon view
    if (currentView === 'recon-view') {
      // Shift+/ or ESC to return to dashboard
      if ((key.shift && key.name === '/') || key.name === 'escape') {
        setCurrentView('overview');
        return;
      }
      return; // Let ReconView handle scrolling
    }

    // Overview keyboard handling
    if (showNewAgentInput) {
      if (key.name === 'escape') {
        if (showMentions) {
          setShowMentions(false);
        } else {
          setShowNewAgentInput(false);
          setNewAgentInput('');
        }
        return;
      }
      // Only handle Enter if autocomplete is not showing
      if (key.name === 'return' && !showMentions) {
        handleCreateNewAgent();
        return;
      }
      return; // Let input and MentionAutocomplete handle other keys
    }

    // N - New agent
    if (key.name === 'n' || key.name === 'N') {
      setShowNewAgentInput(true);
      return;
    }

    // R - View recon agent messages
    if (key.name === 'r' || key.name === 'R') {
      setCurrentView('recon-view');
      return;
    }

    // Tab - Switch between agents and endpoints
    if (key.name === 'tab') {
      setFocusedArea(prev => prev === 'agents' ? 'endpoints' : 'agents');
      return;
    }

    // Shift+/ - Exit dashboard
    if (key.shift && key.name === '/') {
      route.navigate({ type: 'base', path: 'home' });
      return;
    }

    // ESC - Exit
    if (key.name === 'escape') {
      route.navigate({ type: 'base', path: 'home' });
      return;
    }

    // Arrow navigation
    if (focusedArea === 'agents' && agents.length > 0) {
      if (key.name === 'up') {
        setFocusedAgentIndex(prev => Math.max(0, prev - 2));
        return;
      }
      if (key.name === 'down') {
        setFocusedAgentIndex(prev => Math.min(agents.length - 1, prev + 2));
        return;
      }
      if (key.name === 'left') {
        setFocusedAgentIndex(prev => Math.max(0, prev - 1));
        return;
      }
      if (key.name === 'right') {
        setFocusedAgentIndex(prev => Math.min(agents.length - 1, prev + 1));
        return;
      }
      if (key.name === 'return') {
        const agent = agents[focusedAgentIndex];
        if (agent) {
          setActiveAgentId(agent.id);
          setCurrentView('agent-chat');
        }
        return;
      }
    }

    if (focusedArea === 'endpoints' && endpoints.length > 0) {
      if (key.name === 'up') {
        setFocusedEndpointIndex(prev => Math.max(0, prev - 1));
        return;
      }
      if (key.name === 'down') {
        setFocusedEndpointIndex(prev => Math.min(endpoints.length - 1, prev + 1));
        return;
      }
      if (key.name === 'return') {
        const endpoint = endpoints[focusedEndpointIndex];
        if (endpoint) {
          spawnAgentFromEndpoint(endpoint);
        }
        return;
      }
    }
  });

  // Compute metrics
  const metrics = useMemo(() => ({
    totalAgents: agents.length,
    activeAgents: agents.filter(a => a.status === 'running').length,
    completedAgents: agents.filter(a => a.status === 'completed').length,
    discoveredEndpoints: endpoints.length,
    duration: Math.floor((Date.now() - startTime.getTime()) / 1000),
  }), [agents, endpoints, startTime]);

  // Render agent chat view
  if (currentView === 'agent-chat' && activeAgent) {
    return (
      <AgentChatView
        agent={activeAgent}
        endpoints={endpoints}
        onSendMessage={(message) => {
          activeAgent.agentRef.injectUserMessage(message);
        }}
        onBack={() => setCurrentView('overview')}
        onStop={() => {
          activeAgent.agentRef.stop();
          setCurrentView('overview');
        }}
      />
    );
  }

  // Render recon view
  if (currentView === 'recon-view') {
    return (
      <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
        {/* Header */}
        <box
          flexDirection="row"
          justifyContent="space-between"
          paddingLeft={2}
          paddingRight={2}
          paddingTop={1}
          paddingBottom={1}
          border={["bottom"]}
          borderColor={dimText}
        >
          <box flexDirection="column">
            <text fg={creamText}>
              <span fg={reconStatus === 'running' ? greenBullet : dimText}>
                {reconStatus === 'running' ? '◐ ' : '✓ '}
              </span>
              Attack Surface Discovery
            </text>
            <text fg={dimText}>Target: {session.targets[0]}</text>
          </box>
          <text fg={dimText}>
            {reconStatus === 'running' ? 'Running...' : `${endpoints.length} targets found`}
          </text>
        </box>

        {/* Message stream */}
        <box flexGrow={1} padding={1}>
          <AgentDisplay
            messages={reconMessages}
            isStreaming={reconStatus === 'running'}
            focused={true}
          />
        </box>

        {/* Footer */}
        <box
          flexDirection="row"
          justifyContent="space-between"
          paddingLeft={2}
          paddingRight={2}
          paddingTop={1}
          paddingBottom={1}
          border={["top"]}
          borderColor={dimText}
        >
          <text fg={dimText}>
            Messages: {reconMessages.length} | Status: {reconStatus}
          </text>
          <text fg={dimText}>
            [ESC] or [Shift+/] Back to dashboard
          </text>
        </box>
      </box>
    );
  }

  // Render overview
  return (
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {/* Header */}
      <box flexDirection="row" justifyContent="space-between" paddingLeft={2} paddingRight={2} paddingTop={1} paddingBottom={1}>
        <box flexDirection="column">
          <text fg={creamText}>Driver Mode - {session.name}</text>
          <text fg={dimText}>Target: {session.targets[0]}</text>
        </box>
        <box flexDirection="row" gap={2}>
          <text fg={reconStatus === 'running' ? greenBullet : dimText}>
            Recon: {reconStatus === 'running' ? 'Running...' : reconStatus === 'completed' ? 'Complete' : 'Idle'}
          </text>
        </box>
      </box>

      {/* Main content */}
      <box flexDirection="row" flexGrow={1} gap={2} paddingLeft={2} paddingRight={2}>
        {/* Agent grid */}
        <box flexDirection="column" flexGrow={2} gap={1}>
          <text fg={focusedArea === 'agents' ? creamText : dimText}>
            Agents ({agents.length})
          </text>

          {agents.length === 0 ? (
            <box
              flexGrow={1}
              alignItems="center"
              justifyContent="center"
              border
              borderColor={dimText}
            >
              <text fg={dimText}>No agents yet. Press [N] to create one or select an endpoint.</text>
            </box>
          ) : (
            <box flexDirection="row" flexWrap="wrap" gap={1}>
              {agents.map((agent, index) => (
                <AgentCard
                  key={agent.id}
                  agent={agent}
                  focused={focusedArea === 'agents' && focusedAgentIndex === index}
                />
              ))}
            </box>
          )}
        </box>

        {/* Endpoint sidebar */}
        <EndpointSidebar
          endpoints={endpoints}
          focusedIndex={focusedArea === 'endpoints' ? focusedEndpointIndex : -1}
          reconStatus={reconStatus}
          onSelectEndpoint={spawnAgentFromEndpoint}
        />
      </box>

      {/* New agent input overlay */}
      {showNewAgentInput && (
        <box
          position="absolute"
          bottom={4}
          left={2}
          right={2}
          border
          borderColor={greenBullet}
          backgroundColor={darkBg}
          padding={1}
        >
           {showMentions && (
              <MentionAutocomplete
                endpoints={endpoints}
                query={mentionQuery}
                onSelect={handleMentionSelect}
                onClose={() => setShowMentions(false)}
            />
          )}
          <text fg={creamText}>New Agent Target (use @endpoint or describe target): </text>
          <box flexDirection="row" width={"100%"} height={2}>
            <input
              width={"100%"}
              height={"100%"}
              value={newAgentInput}
              onInput={handleInput}
              focused={!loading}
              textColor={loading ? "gray" : "white"}
              placeholder="@http://localhost:3000/api/user test for SQL injection..."
            />
            {loading &&
             <SpinnerDots fg="gray"/>
            }
          </box>
        </box>
      )}

      {/* Metrics bar */}
      <box
        flexDirection="row"
        justifyContent="space-between"
        paddingLeft={2}
        paddingRight={2}
        paddingTop={1}
        paddingBottom={1}
        border={["top"]}
        borderColor={dimText}
      >
        <text fg={dimText}>
          Agents: {metrics.activeAgents}/{metrics.totalAgents} active |
          Endpoints: {metrics.discoveredEndpoints} |
          Duration: {formatDuration(metrics.duration)}
        </text>
        <text fg={dimText}>
          [N] New Agent | [R] View Recon | [Tab] Switch | [Enter] Select | [Shift+/] Exit
        </text>
      </box>
    </box>
  );
}

/**
 * Agent card component
 */
function AgentCard({ agent, focused }: { agent: DriverAgent; focused: boolean }) {
  const statusIcon = {
    running: '◐',
    paused: '◑',
    completed: '✓',
    failed: '✗',
  }[agent.status];

  const statusColor = {
    running: greenBullet,
    paused: RGBA.fromInts(255, 193, 7, 255),
    completed: greenBullet,
    failed: RGBA.fromInts(244, 67, 54, 255),
  }[agent.status];

  return (
    <box
      width="48%"
      border
      borderColor={focused ? greenBullet : dimText}
      padding={1}
      flexDirection="column"
      gap={0}
    >
      <text fg={focused ? creamText : dimText}>
        <span fg={statusColor}>{statusIcon} </span>
        {agent.name}
      </text>
      <text fg={dimText}>
        {agent.target.target.length > 40 ? agent.target.target.substring(0, 37) + '...' : agent.target.target}
      </text>
      <text fg={dimText}>
        {agent.messages.length} messages
      </text>
    </box>
  );
}

/**
 * Format duration as MM:SS
 */
function formatDuration(seconds: number): string {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}:${secs.toString().padStart(2, '0')}`;
}
