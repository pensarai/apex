#!/usr/bin/env bun
import { render } from "@opentui/react";
import { useState, useEffect } from "react";
import AgentDisplay from "./src/tui/components/agent-display";
import type { Message, ToolMessage } from "./src/core/messages";
import type { Subagent } from "./src/tui/components/hooks/pentestAgent";

/**
 * Test file V3 - Simulates REAL tool call update behavior
 * where tool messages are UPDATED in place (pending -> completed)
 * NOT created as duplicates
 *
 * Run with: bun run test-agent-display-v3.tsx
 */

interface ToolCallEvent {
  type: "tool-call" | "tool-result";
  toolCallId: string;
  toolName: string;
  description: string;
  args: any;
  timestamp: number;
}

// Generate test data
function generateTestData() {
  const mainMessages: Message[] = [];
  const subagentsData: Array<{
    id: string;
    name: string;
    type: "attack-surface" | "pentest";
    events: Array<
      { type: "message"; content: string; timestamp: number } | ToolCallEvent
    >;
  }> = [];

  const baseTime = Date.now();

  // Create 16 subagents with lots of tool call events
  for (let i = 0; i < 16; i++) {
    const events: Array<
      { type: "message"; content: string; timestamp: number } | ToolCallEvent
    > = [];
    let offset = 1000;

    events.push({
      type: "message",
      content: `Starting subagent ${i + 1} testing...`,
      timestamp: offset,
    });
    offset += 1000;

    // Create 20 tool calls per subagent
    for (let j = 0; j < 20; j++) {
      const toolCallId = `sub-${i}-tool-${j}`;

      // Tool call starts (pending)
      events.push({
        type: "tool-call",
        toolCallId,
        toolName: `test_tool_${j}`,
        description: `Running test ${j + 1}/20`,
        args: { test: j },
        timestamp: offset,
      });
      offset += 2000;

      // Tool call completes
      events.push({
        type: "tool-result",
        toolCallId,
        toolName: `test_tool_${j}`,
        description: `Running test ${j + 1}/20`,
        args: { test: j },
        timestamp: offset,
      });
      offset += 500;

      // Analysis message every 5 tools
      if ((j + 1) % 5 === 0) {
        events.push({
          type: "message",
          content: `Completed ${j + 1} tests, analyzing results...`,
          timestamp: offset,
        });
        offset += 1000;
      }
    }

    events.push({
      type: "message",
      content: `Subagent ${i + 1} complete. All 20 tests passed.`,
      timestamp: offset,
    });

    subagentsData.push({
      id: `subagent-${i + 1}`,
      name: `Security Test Suite ${i + 1}`,
      type: i === 0 ? "attack-surface" : "pentest",
      events,
    });
  }

  return { mainMessages, subagentsData };
}

function App() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [subagents, setSubagents] = useState<Subagent[]>([]);
  const [currentSubagentIndex, setCurrentSubagentIndex] = useState(0);
  const [currentEventIndex, setCurrentEventIndex] = useState(0);

  const testData = generateTestData();

  // Simulate streaming subagent events
  useEffect(() => {
    if (currentSubagentIndex >= testData.subagentsData.length) {
      console.log("=== ALL SUBAGENTS LOADED ===");
      console.log(`Total subagents: ${subagents.length}`);
      console.log(
        "Subagent details:",
        subagents.map((s) => ({
          name: s.name,
          messages: s.messages.length,
          toolCalls: s.messages.filter((m) => m.role === "tool").length,
          completed: s.messages.filter(
            (m) =>
              m.role === "tool" && (m as ToolMessage).status === "completed"
          ).length,
        }))
      );
      return;
    }

    const currentSubagentData = testData.subagentsData[currentSubagentIndex];
    if (!currentSubagentData) return;

    const events = currentSubagentData.events;

    if (currentEventIndex === 0) {
      // Initialize new subagent
      console.log(
        `>>> Adding subagent ${currentSubagentIndex + 1}/16: ${
          currentSubagentData.name
        }`
      );
      setSubagents((prev) => [
        ...prev,
        {
          id: currentSubagentData.id,
          name: currentSubagentData.name,
          type: currentSubagentData.type,
          target: "example.com",
          messages: [],
          createdAt: new Date(),
          status: "pending",
        },
      ]);
    }

    if (currentEventIndex < events.length) {
      const event = events[currentEventIndex];
      if (!event) return;

      setSubagents((prev) => {
        const updated = [...prev];
        const subagent = updated[currentSubagentIndex];
        if (!subagent) return prev;

        const messages = [...subagent.messages];

        if (event.type === "message") {
          // Add assistant message
          messages.push({
            role: "assistant",
            content: event.content,
            createdAt: new Date(),
          });
        } else if (event.type === "tool-call") {
          // Add pending tool message
          messages.push({
            role: "tool",
            status: "pending",
            toolCallId: event.toolCallId,
            content: event.description,
            args: event.args,
            toolName: event.toolName,
            createdAt: new Date(),
          });
        } else if (event.type === "tool-result") {
          // UPDATE existing tool message to completed
          const existingIndex = messages.findIndex(
            (m) =>
              m.role === "tool" &&
              (m as ToolMessage).toolCallId === event.toolCallId
          );

          if (existingIndex !== -1) {
            // Update the existing message
            messages[existingIndex] = {
              role: "tool",
              status: "completed",
              toolCallId: event.toolCallId,
              content: `✓ ${event.description}`,
              args: event.args,
              toolName: event.toolName,
              createdAt: new Date(),
            };
          }
        }

        updated[currentSubagentIndex] = { ...subagent, messages };
        return updated;
      });

      setTimeout(() => {
        setCurrentEventIndex(currentEventIndex + 1);
      }, 10); // Fast streaming
    } else {
      // Move to next subagent
      setSubagents((prev) => {
        const updated = [...prev];
        if (updated[currentSubagentIndex]) {
          updated[currentSubagentIndex] = {
            ...updated[currentSubagentIndex],
            status: "completed",
          };
        }
        return updated;
      });

      console.log(`    Completed subagent ${currentSubagentIndex + 1}`);

      setTimeout(() => {
        setCurrentSubagentIndex(currentSubagentIndex + 1);
        setCurrentEventIndex(0);
      }, 100); // Pause between subagents
    }
  }, [currentSubagentIndex, currentEventIndex]);

  // Log render info
  const subagentToolCalls = subagents.reduce(
    (sum, s) => sum + s.messages.filter((m) => m.role === "tool").length,
    0
  );

  console.log(
    `[RENDER] Subagents: ${subagents.length}/16, Total tool messages: ${subagentToolCalls}`
  );

  return (
    <box flexDirection="column" width="100%" height="100%">
      <box
        padding={1}
        backgroundColor="rgb(40, 40, 40)"
        border={["bottom"]}
        borderColor="green"
      >
        <text fg="green">Test V3 - Real Tool Call Update Simulation</text>
        <text>
          {" "}
          | Subagents: {subagents.length}/16 | Tool Calls: {subagentToolCalls}
        </text>
      </box>

      <AgentDisplay
        messages={messages}
        subagents={subagents}
        isStreaming={currentSubagentIndex < 16}
      />

      <box
        padding={1}
        backgroundColor="rgb(40, 40, 40)"
        border={["top"]}
        borderColor="green"
      >
        <text fg="yellow">
          ⚠ CLICK FIRST SUBAGENT to open/close • Watch if others disappear
        </text>
      </box>
    </box>
  );
}

render(<App />, {
  exitOnCtrlC: true,
});
