# Subagent Message Storage

## Overview

The thorough pentest agent (orchestrator) now captures and stores complete message histories from all subagents in the orchestrator's session folder. This provides full traceability, debugging capability, and analysis of subagent behavior.

## Implementation

### Changes Made

1. **New Function**: `saveSubagentMessages()` in `src/core/messages/index.ts`

   - Saves subagent messages to orchestrator session
   - Creates directory structure: `subagents/<subagent-id>/`
   - Stores both messages and metadata

2. **Updated**: `get_attack_surface` tool in `thoroughPentestAgent/agent.ts`

   - Captures all messages from attack surface agent
   - Saves to `subagents/attack-surface-<session-id>/`
   - Includes metadata (type, target, objective, timing)

3. **Updated**: `run_pentest_agents` tool in `thoroughPentestAgent/agent.ts`
   - Captures messages from each pentest agent
   - Saves to `subagents/pentest-<N>-<session-id>/`
   - Parallel execution with message capture

## Directory Structure

```
sessions/<orchestrator-session-id>/
  ├── messages.json                      # Orchestrator's own messages
  ├── comprehensive-pentest-report.md
  ├── attack-surface-results.json
  └── subagents/
      ├── attack-surface-abc123/
      │   ├── messages.json              # Complete message history
      │   └── metadata.json              # Subagent metadata
      ├── pentest-1-def456/
      │   ├── messages.json
      │   └── metadata.json
      ├── pentest-2-ghi789/
      │   ├── messages.json
      │   └── metadata.json
      └── ...
```

## Message Format

Each `messages.json` contains the complete conversation stream:

```json
[
  {
    "role": "user",
    "content": "Target: example.com\nObjective: Comprehensive assessment"
  },
  {
    "role": "assistant",
    "content": "I'll begin by performing reconnaissance..."
  },
  {
    "role": "tool",
    "status": "completed",
    "toolCallId": "call_abc123",
    "content": "✓ Executing port scan",
    "toolName": "execute_command",
    "args": {
      "command": "nmap -sV example.com",
      "toolCallDescription": "Executing port scan"
    }
  }
]
```

### Message Types

1. **User Messages**: Initial target and objective
2. **Assistant Messages**: Agent reasoning and explanations
3. **Tool Messages**: Tool calls with status (pending → completed)

## Metadata Format

Each `metadata.json` provides context about the subagent:

```json
{
  "type": "pentest",
  "subagentId": "pentest-1-abc123",
  "target": "admin.example.com",
  "objective": "Test admin panel for authentication bypass",
  "sessionId": "xyz789",
  "sessionPath": "/path/to/subagent/original/session",
  "startTime": "2025-01-10T12:00:00.000Z",
  "endTime": "2025-01-10T12:45:00.000Z",
  "agentIndex": 1
}
```

### Metadata Fields

- **type**: `"attack-surface"` or `"pentest"`
- **subagentId**: Unique identifier within orchestrator session
- **target**: Target being tested
- **objective**: Testing objective
- **sessionId**: Original subagent's session ID
- **sessionPath**: Path to subagent's own session directory
- **startTime**: When subagent started
- **endTime**: When subagent completed
- **agentIndex**: For pentest agents, their spawn order (1, 2, 3, ...)

## Use Cases

### 1. Debugging Failed Subagents

```bash
# Find which subagent failed
cat sessions/<id>/subagents/*/metadata.json | jq '.type, .target'

# Check last messages to see what happened
cat sessions/<id>/subagents/pentest-2-*/messages.json | jq '.[-5:]'
```

### 2. Analyzing Agent Behavior

```bash
# See what tools each agent used
for dir in sessions/<id>/subagents/*/; do
  echo "=== $(basename $dir) ==="
  cat "$dir/messages.json" | jq '[.[] | select(.role == "tool")] | group_by(.toolName) | map({tool: .[0].toolName, count: length})'
done
```

### 3. Extracting Specific Actions

```bash
# Get all nmap commands run by all subagents
find sessions/<id>/subagents -name messages.json -exec \
  jq -r '.[] | select(.toolName == "execute_command") | select(.args.command | contains("nmap")) | .args.command' {} \;
```

### 4. Timeline Reconstruction

```bash
# Build timeline of all subagent activity
for dir in sessions/<id>/subagents/*/; do
  metadata=$(cat "$dir/metadata.json")
  echo "$metadata" | jq '{start: .startTime, end: .endTime, type: .type, target: .target}'
done | jq -s 'sort_by(.start)'
```

### 5. Performance Analysis

```bash
# Calculate duration of each subagent
for dir in sessions/<id>/subagents/*/; do
  metadata=$(cat "$dir/metadata.json")
  type=$(echo "$metadata" | jq -r '.type')
  target=$(echo "$metadata" | jq -r '.target')
  start=$(echo "$metadata" | jq -r '.startTime')
  end=$(echo "$metadata" | jq -r '.endTime')

  # Calculate duration (requires date command or similar)
  echo "$type - $target: $start to $end"
done
```

### 6. Quality Assurance

```bash
# Verify all subagents completed properly
for dir in sessions/<id>/subagents/*/; do
  messages=$(cat "$dir/messages.json")
  tool_count=$(echo "$messages" | jq '[.[] | select(.role == "tool")] | length')

  echo "$(basename $dir): $tool_count tool calls"
done
```

## Benefits

1. **Full Traceability**: Complete record of what each subagent did
2. **Debugging**: Easy to identify where things went wrong
3. **Analysis**: Understand agent decision-making
4. **Audit Trail**: Compliance and documentation
5. **Improvement**: Identify patterns for agent optimization
6. **Replay**: Could theoretically replay agent actions
7. **Testing**: Verify agents are working as expected

## Storage Considerations

### Size Estimates

- **Attack Surface Agent**: ~50-500 KB per session (depends on discovery breadth)
- **Pentest Agent**: ~100 KB - 2 MB per agent (depends on testing depth)
- **Total for 10 agents**: ~1-20 MB

### Cleanup

To manage storage, you can:

```bash
# Remove old subagent messages (keep metadata)
find sessions/*/subagents/*/messages.json -mtime +30 -delete

# Archive old sessions
tar -czf archive-$(date +%Y%m).tar.gz sessions/*/subagents/
```

## Integration with Other Tools

### Export to JSONL for Analysis

```bash
# Export all messages from all subagents
for dir in sessions/<id>/subagents/*/; do
  cat "$dir/messages.json" | jq -c '.[]' >> all-messages.jsonl
done
```

### Generate Subagent Report

```bash
# Create summary of all subagent activity
echo "# Subagent Activity Report" > subagent-report.md
echo "" >> subagent-report.md

for dir in sessions/<id>/subagents/*/; do
  metadata=$(cat "$dir/metadata.json")
  messages=$(cat "$dir/messages.json")

  type=$(echo "$metadata" | jq -r '.type')
  target=$(echo "$metadata" | jq -r '.target')
  tool_count=$(echo "$messages" | jq '[.[] | select(.role == "tool")] | length')

  echo "## $type - $target" >> subagent-report.md
  echo "- Tools used: $tool_count" >> subagent-report.md
  echo "" >> subagent-report.md
done
```

## Future Enhancements

Potential improvements:

1. **Streaming Storage**: Save messages incrementally during execution
2. **Compression**: Compress older message files automatically
3. **Indexing**: Create searchable index of all messages
4. **Visualization**: Build timeline views of subagent activity
5. **Comparison**: Compare message patterns across runs
6. **Filtering**: CLI tool to query messages by tool, target, time, etc.
7. **Export Formats**: Convert to HTML, PDF, or other formats
8. **Statistics**: Automatic calculation of metrics (tools per agent, etc.)

## API Usage

### Saving Subagent Messages

```typescript
import { saveSubagentMessages } from "@/core/messages";

// Within orchestrator tool
saveSubagentMessages(
  orchestratorSession, // Parent session
  subagentId, // Unique ID like "pentest-1-abc123"
  messages // Array of Message objects
);
```

### Reading Subagent Messages

```typescript
import { readFileSync } from "fs";
import { join } from "path";

// Read messages
const messagesPath = join(
  orchestratorSession.rootPath,
  "subagents",
  subagentId,
  "messages.json"
);
const messages = JSON.parse(readFileSync(messagesPath, "utf-8"));

// Read metadata
const metadataPath = join(
  orchestratorSession.rootPath,
  "subagents",
  subagentId,
  "metadata.json"
);
const metadata = JSON.parse(readFileSync(metadataPath, "utf-8"));
```

## Summary

Subagent message storage provides complete transparency into the thorough pentest orchestration process. Every action taken by every subagent is recorded and can be analyzed, debugged, or replayed. This is essential for:

- Understanding what happened during complex multi-agent engagements
- Debugging issues with specific subagents
- Improving agent prompts and behavior
- Compliance and audit requirements
- Quality assurance and testing

The storage is efficient, well-organized, and provides all the data needed for comprehensive analysis of the entire penetration testing engagement.
