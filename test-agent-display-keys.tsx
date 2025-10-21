#!/usr/bin/env bun
import { render } from "@opentui/react";
import { useState, useEffect } from "react";
import AgentDisplay from "./src/tui/components/agent-display";
import type { Message, ToolMessage } from "./src/core/messages";
import type { Subagent } from "./src/tui/components/hooks/pentestAgent";

/**
 * Test to diagnose key stability issues
 *
 * ISSUES FOUND in agent-display.tsx:
 * 1. Tool call keys include STATUS: `tool-${toolCallId}-${status}`
 *    - When tool goes pending->completed, key changes
 *    - React thinks it's a new element, remounts siblings
 *
 * 2. Sorting happens on every render (not memoized)
 *    - If timestamps are close, order might fluctuate
 *    - Causes unnecessary re-renders
 *
 * 3. SubAgentDisplay has local state not tied to subagent ID
 *    - If component remounts, open state is lost
 */

function App() {
  const [subagents, setSubagents] = useState<Subagent[]>([]);
  const [phase, setPhase] = useState(0);

  useEffect(() => {
    const baseTime = Date.now();

    if (phase === 0) {
      // Phase 0: Add 5 subagents quickly
      console.log("=== PHASE 0: Adding 5 subagents ===");
      const newSubagents: Subagent[] = [];
      for (let i = 0; i < 5; i++) {
        newSubagents.push({
          id: `subagent-${i + 1}`,
          name: `Test Subagent ${i + 1}`,
          type: "pentest",
          target: "example.com",
          messages: [],
          createdAt: new Date(baseTime + i * 100), // Close timestamps!
          status: "completed",
        });
      }
      setSubagents(newSubagents);

      setTimeout(() => setPhase(1), 2000);
    } else if (phase === 1) {
      // Phase 1: Add messages with tool calls to subagent 2
      console.log("=== PHASE 1: Adding tool calls to subagent 2 ===");
      console.log("Watch if other subagents disappear!");

      setSubagents((prev) => {
        const updated = [...prev];
        if (updated[1]) {
          // Add PENDING tool call
          updated[1] = {
            ...updated[1],
            messages: [
              {
                role: "assistant",
                content: "Starting tests...",
                createdAt: new Date(),
              },
              {
                role: "tool",
                status: "pending",
                toolCallId: "test-tool-1",
                content: "Running security scan",
                args: {},
                toolName: "security_scan",
                createdAt: new Date(),
              },
            ],
          };
        }
        return updated;
      });

      setTimeout(() => setPhase(2), 2000);
    } else if (phase === 2) {
      // Phase 2: Update tool call to completed
      console.log("=== PHASE 2: Updating tool call to completed ===");
      console.log(
        "KEY WILL CHANGE: tool-test-tool-1-pending -> tool-test-tool-1-completed"
      );
      console.log(
        "This causes React remount! Watch if subagents 3-5 disappear!"
      );

      setSubagents((prev) => {
        const updated = [...prev];
        if (updated[1]) {
          // UPDATE tool call to completed (key changes!)
          const messages = [...updated[1].messages];
          const toolIndex = messages.findIndex(
            (m) =>
              m.role === "tool" &&
              (m as ToolMessage).toolCallId === "test-tool-1"
          );

          if (toolIndex !== -1) {
            messages[toolIndex] = {
              role: "tool",
              status: "completed", // STATUS CHANGED - KEY WILL CHANGE!
              toolCallId: "test-tool-1",
              content: "✓ Running security scan",
              args: {},
              toolName: "security_scan",
              createdAt: new Date(),
            };
          }

          updated[1] = { ...updated[1], messages };
        }
        return updated;
      });

      setTimeout(() => setPhase(3), 2000);
    } else if (phase === 3) {
      // Phase 3: Add more subagents with same timestamps
      console.log("=== PHASE 3: Adding subagents with SAME timestamp ===");
      console.log("Sorting will be unstable!");

      const sameTime = new Date(baseTime + 500);
      setSubagents((prev) => [
        ...prev,
        {
          id: `subagent-6`,
          name: `Subagent 6 (same timestamp)`,
          type: "pentest",
          target: "example.com",
          messages: [],
          createdAt: sameTime,
          status: "completed",
        },
        {
          id: `subagent-7`,
          name: `Subagent 7 (same timestamp)`,
          type: "pentest",
          target: "example.com",
          messages: [],
          createdAt: sameTime, // SAME timestamp as subagent 6!
          status: "completed",
        },
      ]);

      setTimeout(() => setPhase(4), 2000);
    } else if (phase === 4) {
      console.log("=== PHASE 4: Force re-render ===");
      console.log("Sorting might reorder subagents 6 & 7 (same timestamp)");

      // Just trigger a re-render
      setSubagents((prev) => [...prev]);

      setTimeout(() => {
        console.log("=== TEST COMPLETE ===");
        console.log("Open/close subagent dropdowns and watch console");
        setPhase(5);
      }, 2000);
    }
  }, [phase]);

  console.log(`[RENDER] Phase ${phase}, Subagents: ${subagents.length}`);
  console.log("Subagent order:", subagents.map((s) => s.id).join(", "));

  return (
    <box flexDirection="column" width="100%" height="100%">
      <box
        padding={1}
        backgroundColor="rgb(40, 40, 40)"
        border={["bottom"]}
        borderColor="green"
      >
        <text fg="green">Key Stability Test - Phase {phase}/5</text>
        <text> | Subagents: {subagents.length}</text>
      </box>

      <AgentDisplay
        messages={[]}
        subagents={subagents}
        isStreaming={phase < 5}
      />

      <box
        padding={1}
        backgroundColor="rgb(40, 40, 40)"
        border={["top"]}
        borderColor="green"
      >
        <box flexDirection="column">
          <text fg="yellow">Issues to watch:</text>
          <text>
            1. Tool call key changes when status updates (pending→completed)
          </text>
          <text>2. Subagents with same timestamp get unstable sort order</text>
          <text>3. Opening dropdown in one subagent affects others</text>
        </box>
      </box>
    </box>
  );
}

render(<App />, {
  exitOnCtrlC: true,
});
