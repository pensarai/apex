# Subagent Real-Time Tracking Implementation

## Overview

The thorough pentest orchestrator now supports real-time tracking of all subagents in the UI. This provides live visibility into what each subagent is doing, including message streams, status updates, and completion notifications.

## Implementation

### 1. Hook for Thorough Pentest Agent

**File**: `src/tui/components/hooks/thoroughPentestAgent.ts`

This custom React hook manages the state for the thorough pentest agent with subagent tracking:

```typescript
export type Subagent = {
  id: string; // Unique identifier like "pentest-1-abc123"
  name: string; // Display name like "Pentest 1: admin.example.com"
  type: "attack-surface" | "pentest";
  target: string; // Target being tested
  messages: Message[]; // Real-time message stream
  status: "pending" | "running" | "completed" | "failed";
};
```

**Key Features:**

- `subagents` state array tracks all spawned subagents
- Real-time message streaming to each subagent
- Status tracking (pending → running → completed/failed)
- Integrates with existing agent provider for token tracking

### 2. Backend Callback Support

**File**: `src/core/agent/thoroughPentestAgent/agent.ts`

Added three callback types to `RunAgentProps`:

```typescript
export interface SubagentSpawnInfo {
  id: string;
  name: string;
  type: "attack-surface" | "pentest";
  target: string;
}

export interface RunAgentProps {
  // ... existing props
  onSubagentSpawn?: (info: SubagentSpawnInfo) => void;
  onSubagentMessage?: (subagentId: string, message: Message) => void;
  onSubagentComplete?: (subagentId: string, success: boolean) => void;
}
```

**Callback Flow:**

1. **onSubagentSpawn**: Called when a subagent is launched

   - Provides ID, name, type, and target
   - UI adds subagent to array with "running" status

2. **onSubagentMessage**: Called for every message from the subagent

   - User messages (initial target/objective)
   - Assistant messages (reasoning, explanations)
   - Tool messages (command execution, scans)
   - UI updates the specific subagent's message array

3. **onSubagentComplete**: Called when subagent finishes
   - Provides success/failure status
   - UI updates status to "completed" or "failed"

### 3. Integration Points

#### Attack Surface Agent (`get_attack_surface` tool)

```typescript
// 1. Spawn notification
if (onSubagentSpawn) {
  onSubagentSpawn({
    id: subagentId,
    name: `Attack Surface Analysis: ${target}`,
    type: "attack-surface",
    target,
  });
}

// 2. Stream messages
for await (const delta of result.fullStream) {
  // ... process delta
  if (onSubagentMessage) {
    onSubagentMessage(subagentId, message);
  }
}

// 3. Completion
if (onSubagentComplete) {
  onSubagentComplete(subagentId, true);
}
```

#### Pentest Agents (`run_pentest_agents` tool)

Same pattern for each pentest agent running in parallel:

- Spawn notification before streaming starts
- Message callbacks during streaming
- Completion notification after finishing

Each pentest agent gets a unique ID: `pentest-1-abc123`, `pentest-2-def456`, etc.

## UI Integration

### Using the Hook

```typescript
import useThoroughPentestAgent from "./hooks/thoroughPentestAgent";

function ThoroughPentestDisplay() {
  const {
    target,
    setTarget,
    objective,
    setObjective,
    messages, // Orchestrator messages
    subagents, // Array of subagent data
    isExecuting,
    beginExecution,
    // ... other properties
  } = useThoroughPentestAgent();

  return (
    <div>
      {/* Orchestrator messages */}
      <MessagesDisplay messages={messages} />

      {/* Subagent tracking */}
      <SubagentsPanel subagents={subagents} />
    </div>
  );
}
```

### Displaying Subagents

You can now display subagent activity in real-time:

```typescript
{
  subagents.map((subagent) => (
    <SubagentCard key={subagent.id}>
      <h3>{subagent.name}</h3>
      <Status status={subagent.status} />
      <MessageCount count={subagent.messages.length} />
      <MessagesStream messages={subagent.messages} />
    </SubagentCard>
  ));
}
```

## Benefits

### 1. Real-Time Visibility

- See which subagents are running
- Watch live message streams from each
- Know when each completes

### 2. Debugging

- Identify which subagent failed
- See exactly what each agent is doing
- Track message flow per agent

### 3. User Experience

- Progress indication for long-running tests
- Transparency into orchestration
- Better understanding of agent workflow

### 4. Monitoring

- Track parallel execution
- Monitor resource usage
- Identify bottlenecks

## Example Flow

### User starts thorough pentest:

```
Target: example.com
Objective: Comprehensive assessment
```

### Orchestrator spawns attack surface agent:

```
onSubagentSpawn({
  id: "attack-surface-abc123",
  name: "Attack Surface Analysis: example.com",
  type: "attack-surface",
  target: "example.com"
})
```

### UI updates:

```
Subagents:
  ▶ Attack Surface Analysis: example.com (running)
    - Messages: 3
```

### Messages stream in:

```
onSubagentMessage("attack-surface-abc123", {
  role: "assistant",
  content: "Beginning reconnaissance..."
})

onSubagentMessage("attack-surface-abc123", {
  role: "tool",
  toolName: "execute_command",
  content: "✓ Executing nmap scan"
})
```

### UI updates in real-time:

```
Subagents:
  ▶ Attack Surface Analysis: example.com (running)
    - Messages: 15
    - Last: ✓ Executing nmap scan
```

### Attack surface completes:

```
onSubagentComplete("attack-surface-abc123", true)
```

### UI updates:

```
Subagents:
  ✓ Attack Surface Analysis: example.com (completed)
    - Messages: 47
    - Discovered 8 high-value targets
```

### Orchestrator spawns pentest agents:

```
onSubagentSpawn({
  id: "pentest-1-def456",
  name: "Pentest 1: admin.example.com",
  type: "pentest",
  target: "admin.example.com"
})

onSubagentSpawn({
  id: "pentest-2-ghi789",
  name: "Pentest 2: api.example.com",
  type: "pentest",
  target: "api.example.com"
})

// ... more agents
```

### UI shows parallel execution:

```
Subagents:
  ✓ Attack Surface Analysis: example.com (completed)
  ▶ Pentest 1: admin.example.com (running)
  ▶ Pentest 2: api.example.com (running)
  ▶ Pentest 3: dev.example.com (running)
```

### As agents complete:

```
Subagents:
  ✓ Attack Surface Analysis: example.com (completed)
  ✓ Pentest 1: admin.example.com (completed)
  ▶ Pentest 2: api.example.com (running)
  ✓ Pentest 3: dev.example.com (completed)
```

## UI Components to Build

### 1. Subagent Status Indicator

```typescript
function SubagentStatus({ status }: { status: Subagent["status"] }) {
  const icons = {
    pending: "⏳",
    running: "▶️",
    completed: "✅",
    failed: "❌",
  };
  return <span>{icons[status]}</span>;
}
```

### 2. Subagent Card

```typescript
function SubagentCard({ subagent }: { subagent: Subagent }) {
  return (
    <div className="subagent-card">
      <header>
        <SubagentStatus status={subagent.status} />
        <h3>{subagent.name}</h3>
        <span>{subagent.messages.length} messages</span>
      </header>

      {subagent.messages.length > 0 && (
        <div className="latest-message">
          {subagent.messages[subagent.messages.length - 1].content}
        </div>
      )}

      {subagent.status === "running" && <ProgressSpinner />}
    </div>
  );
}
```

### 3. Subagents Panel

```typescript
function SubagentsPanel({ subagents }: { subagents: Subagent[] }) {
  const running = subagents.filter((s) => s.status === "running").length;
  const completed = subagents.filter((s) => s.status === "completed").length;

  return (
    <div className="subagents-panel">
      <header>
        <h2>Subagents</h2>
        <span>
          {running} running, {completed} completed
        </span>
      </header>

      <div className="subagents-list">
        {subagents.map((subagent) => (
          <SubagentCard key={subagent.id} subagent={subagent} />
        ))}
      </div>
    </div>
  );
}
```

## State Management

The hook manages state efficiently:

```typescript
// Adding a new subagent
setSubagents((prev) => [
  ...prev,
  {
    id: subagentInfo.id,
    name: subagentInfo.name,
    type: subagentInfo.type,
    target: subagentInfo.target,
    messages: [],
    status: "running",
  },
]);

// Updating messages for a specific subagent
setSubagents((prev) =>
  prev.map((sub) =>
    sub.id === subagentId
      ? { ...sub, messages: [...sub.messages, message] }
      : sub
  )
);

// Updating status
setSubagents((prev) =>
  prev.map((sub) =>
    sub.id === subagentId
      ? { ...sub, status: success ? "completed" : "failed" }
      : sub
  )
);
```

## Performance Considerations

### Message Streaming

- Messages update in real-time but don't block UI
- React efficiently diffs only changed subagent
- Large message arrays handled via virtual scrolling if needed

### Parallel Execution

- Multiple subagents stream simultaneously
- No blocking between subagents
- UI updates asynchronously

### Memory

- Each subagent stores complete message history
- For very long tests, consider:
  - Limiting message history per subagent
  - Collapsing completed subagents
  - Pagination for message display

## Future Enhancements

1. **Expandable Subagents**: Click to expand/collapse full message history
2. **Filtering**: Show only running, completed, or failed subagents
3. **Search**: Search across all subagent messages
4. **Export**: Export subagent data to JSON/CSV
5. **Replay**: Replay subagent execution from messages
6. **Statistics**: Show metrics (tools used, duration, etc.)
7. **Live Tail**: Auto-scroll to latest messages
8. **Notifications**: Alert when subagents complete or fail

## Summary

Real-time subagent tracking provides complete visibility into the thorough pentest orchestration process. Every subagent spawn, message, and completion is tracked and displayed in the UI, enabling:

- Transparent multi-agent workflows
- Real-time progress monitoring
- Easy debugging and analysis
- Better user experience
- Full auditability

The implementation uses React hooks for state management and callback functions to bridge the backend agent execution with frontend updates. All messages are streamed in real-time while also being saved to disk for later analysis.
