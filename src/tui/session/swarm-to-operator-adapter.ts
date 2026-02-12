/**
 * Adapter: Swarm Session State -> Operator Context
 *
 * Converts auto-mode (swarm) session data into the operator context shape
 * (DisplayMessage[] + Endpoint[]) so an auto-mode session can be continued
 * in operator mode with full awareness of prior discoveries.
 */

import type { LoadedSessionState } from "../../core/session/loader";
import type { DisplayMessage } from "../components/agent-display";
import type { Endpoint } from "../components/operator-dashboard/types";

export function adaptSwarmStateForOperator(state: LoadedSessionState): {
  messages: DisplayMessage[];
  attackSurface: Endpoint[];
} {
  const messages: DisplayMessage[] = [];

  // Add context summary as system message
  messages.push({
    role: "system",
    content: `Resuming from auto-mode session. ${state.subagents.length} subagent(s) ran. ${state.hasReport ? "Report available." : ""}`,
    createdAt: new Date(),
  });

  // Extract last assistant message from each subagent as a summary
  for (const sub of state.subagents) {
    const assistantMsgs = sub.messages.filter(
      (m) =>
        m.role === "assistant" &&
        typeof m.content === "string" &&
        m.content.trim()
    );
    const lastSummary = assistantMsgs[assistantMsgs.length - 1];
    if (lastSummary) {
      messages.push({
        role: "assistant",
        content: `[${sub.name}] ${lastSummary.content}`,
        createdAt: lastSummary.createdAt,
      });
    }
  }

  // Extract attack surface endpoints from discovery results
  const attackSurface: Endpoint[] = [];
  if (state.attackSurfaceResults?.targets) {
    for (const target of state.attackSurfaceResults.targets) {
      attackSurface.push({
        id: `synth-${attackSurface.length}`,
        method: "GET",
        path: target.target,
        status: "discovered" as any,
        category: target.objective || "unknown",
      });
    }
  }

  return { messages, attackSurface };
}
