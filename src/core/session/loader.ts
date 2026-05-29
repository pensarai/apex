/**
 * Session State Loader
 *
 * Loads and reconstructs session state from the sessions directory
 * for displaying completed or interrupted sessions in the TUI.
 *
 * Subagent I/O (save + load + filename conventions) lives in persistence.ts.
 * This file orchestrates the higher-level session state assembly.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_FILENAME_MD } from "../report";
import type { SessionInfo } from "./index";
import { loadSubagents, type UIMessage, type UISubagent } from "./persistence";

/**
 * Attack surface results format
 */
export interface AttackSurfaceResults {
  summary?: {
    totalAssets?: number;
    totalDomains?: number;
    analysisComplete?: boolean;
  };
  discoveredAssets?: string[];
  targets?: Array<{
    target: string;
    objective: string;
    rationale?: string;
  }>;
  keyFindings?: string[];
}

/**
 * Loaded session state
 */
interface LoadedSessionState {
  session: SessionInfo;
  subagents: UISubagent[];
  attackSurfaceResults: AttackSurfaceResults | null;
  isComplete: boolean;
  hasReport: boolean;
  interruptedDuringDiscovery: boolean;
}

/**
 * Load attack surface results
 */
export function loadAttackSurfaceResults(
  rootPath: string,
): AttackSurfaceResults | null {
  const resultsPath = join(rootPath, "attack-surface-results.json");
  if (!existsSync(resultsPath)) {
    return null;
  }

  try {
    return JSON.parse(readFileSync(resultsPath, "utf-8"));
  } catch (e) {
    console.error("Failed to load attack surface results:", e);
    return null;
  }
}

/**
 * Check if a final report exists
 */
function hasReport(rootPath: string): boolean {
  const reportPath = join(rootPath, REPORT_FILENAME_MD);
  return existsSync(reportPath);
}

/**
 * Create discovery subagent from logs if no subagent file exists
 */
function createDiscoveryFromLogs(
  rootPath: string,
  session: SessionInfo,
): UISubagent | null {
  const logPath = join(rootPath, "logs", "streamlined-pentest.log");
  if (!existsSync(logPath)) {
    return null;
  }

  try {
    const logContent = readFileSync(logPath, "utf-8");
    const lines = logContent.split("\n").filter(Boolean);

    const messages: UIMessage[] = [];

    for (const line of lines) {
      const match = line.match(
        /^(\d{4}-\d{2}-\d{2}T[\d:.]+Z) - \[(\w+)\] (.+)$/,
      );
      if (!match) continue;

      const [, timestamp, _level, content] = match;
      const createdAt = new Date(timestamp);

      if (content.startsWith("[Tool]")) {
        const toolMatch = content.match(/\[Tool\] (\w+): (.+)/);
        if (toolMatch) {
          messages.push({
            role: "tool",
            content: `✓ ${toolMatch[2]}`,
            createdAt,
            toolName: toolMatch[1],
            status: "completed",
          });
        }
      } else if (content.startsWith("[Step")) {
        const stepMatch = content.match(/\[Step \d+\] (.+)/);
        if (stepMatch) {
          messages.push({
            role: "assistant",
            content: stepMatch[1],
            createdAt,
          });
        }
      }
    }

    if (messages.length === 0) {
      return null;
    }

    return {
      id: "discovery-from-logs",
      name: "Attack Surface Discovery",
      type: "attack-surface",
      target: session.targets[0] || "Unknown",
      messages,
      createdAt: new Date(session.time.created),
      status: "completed",
    };
  } catch (e) {
    console.error("Failed to parse logs:", e);
    return null;
  }
}

/**
 * Load complete session state from execution directory
 */
async function loadSessionState(
  session: SessionInfo,
): Promise<LoadedSessionState> {
  const rootPath = session.rootPath;

  // Load subagents (files + manifest merge) from persistence module
  let subagents = loadSubagents(rootPath);

  // Check if we have attack surface agent in subagents
  const hasAttackSurfaceAgent = subagents.some(
    (s) => s.type === "attack-surface",
  );

  // If no attack surface agent saved, try to reconstruct from logs
  if (!hasAttackSurfaceAgent) {
    const discoveryAgent = createDiscoveryFromLogs(rootPath, session);
    if (discoveryAgent) {
      subagents = [discoveryAgent, ...subagents];
    }
  }

  // Load attack surface results
  const attackSurfaceResults = loadAttackSurfaceResults(rootPath);

  // Check for report
  const hasReportFile = hasReport(rootPath);

  // Detect interrupted discovery: no results file, no report, but discovery logs exist.
  const hasDiscoverySubagent = subagents.some(
    (s) => s.type === "attack-surface",
  );
  const interruptedDuringDiscovery =
    !attackSurfaceResults && !hasReportFile && hasDiscoverySubagent;

  // If discovery was interrupted, mark the discovery subagent as paused (not completed)
  if (interruptedDuringDiscovery) {
    for (let i = 0; i < subagents.length; i++) {
      if (
        subagents[i].type === "attack-surface" &&
        subagents[i].status === "completed"
      ) {
        subagents[i] = { ...subagents[i], status: "paused" };
      }
    }
  }

  const isComplete = hasReportFile;

  return {
    session,
    subagents,
    attackSurfaceResults,
    isComplete,
    hasReport: hasReportFile,
    interruptedDuringDiscovery,
  };
}
