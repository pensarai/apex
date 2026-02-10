/**
 * Session State Loader
 *
 * Loads and reconstructs session state from the executions directory
 * for displaying completed or interrupted sessions in the TUI.
 */

import { join } from "path";
import { existsSync, readdirSync, readFileSync } from "fs";
import type { Session } from "./index";
import type { AuthenticationInfo } from "../agent/orchestrator/types";

/**
 * Message content part from AI SDK format
 */
export interface MessageContentPart {
  type: "text" | "tool-call" | "tool-result";
  text?: string;
  toolCallId?: string;
  toolName?: string;
  input?: Record<string, unknown>;
  output?: unknown;
}

/**
 * Raw message format from saved subagent files
 */
export interface SavedMessage {
  role: "assistant" | "tool" | "user";
  content: MessageContentPart[] | string;
}

/**
 * Saved subagent data format
 */
export interface SavedSubagentData {
  agentName: string;
  timestamp: string;
  target?: string;
  objective?: string;
  vulnerabilityClass?: string;
  toolCallCount?: number;
  stepCount?: number;
  findingsCount?: number;
  status?: string;
  error?: string;
  messages: SavedMessage[];
}

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
 * UI-compatible message format
 */
export interface UIMessage {
  role: "user" | "assistant" | "tool";
  content: string;
  createdAt: Date;
  toolCallId?: string;
  toolName?: string;
  args?: Record<string, unknown>;
  result?: unknown; // Tool output/result
  status?: "pending" | "completed";
}

/**
 * Information needed to resume a paused agent
 */
export interface ResumeInfo {
  target: string;
  objective: string;
  vulnerabilityClass: string;
  authenticationInfo?: AuthenticationInfo;
}

/**
 * UI-compatible subagent format
 */
export interface UISubagent {
  id: string;
  name: string;
  type: "attack-surface" | "pentest";
  target: string;
  messages: UIMessage[];
  createdAt: Date;
  status: "pending" | "completed" | "failed" | "paused" | "canceled";
  resumeInfo?: ResumeInfo;
}

/**
 * Loaded session state
 */
export interface LoadedSessionState {
  session: Session.SessionInfo;
  subagents: UISubagent[];
  attackSurfaceResults: AttackSurfaceResults | null;
  isComplete: boolean;
  hasReport: boolean;
  interruptedDuringDiscovery: boolean;
}

/**
 * Convert saved message content to UI messages
 */
function convertMessagesToUI(
  messages: SavedMessage[],
  baseTime: Date,
): UIMessage[] {
  const uiMessages: UIMessage[] = [];
  let messageIndex = 0;

  // First pass: collect tool results by toolCallId
  const toolResults = new Map<string, unknown>();
  for (const msg of messages) {
    if (Array.isArray(msg.content)) {
      for (const part of msg.content) {
        if (part.type === "tool-result" && part.toolCallId) {
          toolResults.set(part.toolCallId, part.output);
        }
      }
    }
  }

  for (const msg of messages) {
    const createdAt = new Date(baseTime.getTime() + messageIndex * 1000);
    messageIndex++;

    if (typeof msg.content === "string") {
      // Simple text message
      uiMessages.push({
        role: msg.role as "user" | "assistant" | "tool",
        content: msg.content,
        createdAt,
      });
    } else if (Array.isArray(msg.content)) {
      // Complex message with multiple parts
      for (const part of msg.content) {
        if (part.type === "text" && part.text) {
          uiMessages.push({
            role: "assistant",
            content: part.text,
            createdAt,
          });
        } else if (part.type === "tool-call") {
          // Create tool message with result if available
          const toolDescription =
            typeof part.input?.toolCallDescription === "string"
              ? part.input.toolCallDescription
              : part.toolName || "tool";
          const result = part.toolCallId
            ? toolResults.get(part.toolCallId)
            : undefined;
          uiMessages.push({
            role: "tool",
            content: toolDescription,
            createdAt,
            toolCallId: part.toolCallId,
            toolName: part.toolName,
            args: part.input,
            result: result,
            status: "completed",
          });
        }
        // tool-result parts are already collected in the first pass
      }
    }
  }

  return uiMessages;
}

/**
 * Parse subagent filename to extract metadata
 */
function parseSubagentFilename(filename: string): {
  agentType: "attack-surface" | "pentest";
  name: string;
} {
  if (filename.startsWith("attack-surface-agent")) {
    return { agentType: "attack-surface", name: "Attack Surface Discovery" };
  }

  if (filename.startsWith("vuln-test-")) {
    // Extract vulnerability class from filename
    // e.g., vuln-test-command-injection-http---localhost-32768-applica-2025-12-05...
    const parts = filename.replace("vuln-test-", "").split("-");
    const vulnClass = parts[0] || "generic";
    const vulnClassFormatted = vulnClass
      .replace(/-/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
    return {
      agentType: "pentest",
      name: `${vulnClassFormatted} Test`,
    };
  }

  if (filename.startsWith("orchestrator-")) {
    return { agentType: "pentest", name: "Orchestrator Summary" };
  }

  return { agentType: "pentest", name: filename.split("-")[0] || "Unknown" };
}

/**
 * Load all subagent data from the subagents directory
 */
function loadSubagents(rootPath: string): UISubagent[] {
  const subagentsPath = join(rootPath, "subagents");
  if (!existsSync(subagentsPath)) {
    return [];
  }

  const subagents: UISubagent[] = [];
  const files = readdirSync(subagentsPath).filter((f) => f.endsWith(".json"));

  // Sort files by timestamp in filename
  files.sort((a, b) => {
    const timeA = a.match(/\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}/)?.[0] || "";
    const timeB = b.match(/\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}/)?.[0] || "";
    return timeA.localeCompare(timeB);
  });

  for (const file of files) {
    try {
      const filePath = join(subagentsPath, file);
      const data = JSON.parse(
        readFileSync(filePath, "utf-8"),
      ) as SavedSubagentData;

      const { agentType, name } = parseSubagentFilename(file);
      const timestamp = new Date(data.timestamp);

      // Skip orchestrator summary files - they're not real subagents
      if (file.startsWith("orchestrator-")) {
        continue;
      }

      const messages = convertMessagesToUI(data.messages, timestamp);

      // Determine subagent status, prefer explicit status, fallback to findingsCount heuristic
      let status: "pending" | "completed" | "failed" | "canceled" = "completed";
      switch (data.status) {
        case "canceled":
        case "failed":
        case "completed":
        case "pending":
          status = data.status;
          break;
        default:
          if (
            typeof data.findingsCount === "number" &&
            data.findingsCount < 0
          ) {
            status = "failed";
          }
          break;
      }

      subagents.push({
        id: `loaded-${file.replace(".json", "")}`,
        name:
          data.agentName === "attack-surface-agent"
            ? "Attack Surface Discovery"
            : name,
        type: agentType,
        target: data.target || "Unknown",
        messages,
        createdAt: timestamp,
        status,
      });
    } catch (e) {
      console.error(`Failed to load subagent file ${file}:`, e);
    }
  }

  return subagents;
}

/**
 * Load attack surface results
 */
function loadAttackSurfaceResults(
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
  const reportPath = join(rootPath, "comprehensive-pentest-report.md");
  return existsSync(reportPath);
}

/**
 * Create discovery subagent from logs if no subagent file exists
 */
function createDiscoveryFromLogs(
  rootPath: string,
  session: Session.SessionInfo,
): UISubagent | null {
  const logPath = join(rootPath, "logs", "streamlined-pentest.log");
  if (!existsSync(logPath)) {
    return null;
  }

  try {
    const logContent = readFileSync(logPath, "utf-8");
    const lines = logContent.split("\n").filter(Boolean);

    const messages: UIMessage[] = [];
    let stepBuffer = "";

    for (const line of lines) {
      const match = line.match(
        /^(\d{4}-\d{2}-\d{2}T[\d:.]+Z) - \[(\w+)\] (.+)$/,
      );
      if (!match) continue;

      const [, timestamp, level, content] = match;
      const createdAt = new Date(timestamp);

      if (content.startsWith("[Tool]")) {
        // Tool call log
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
        // Step output - assistant message
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
export async function loadSessionState(
  session: Session.SessionInfo,
): Promise<LoadedSessionState> {
  const rootPath = session.rootPath;

  // Load subagents from saved files
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

  // Detect paused agents from manifest (agents that were running when session was interrupted)
  const manifestPath = join(rootPath, "agent-manifest.json");
  if (existsSync(manifestPath)) {
    try {
      const manifest: Array<{
        id: string;
        name: string;
        target: string;
        vulnerabilityClass: string;
        objective: string;
        authInfo?: any;
        status: "running" | "completed";
        spawnedAt: string;
        completedAt?: string;
      }> = JSON.parse(readFileSync(manifestPath, "utf-8"));

      for (const entry of manifest) {
        if (entry.status !== "running") continue;

        const resumeInfo = {
          target: entry.target,
          objective: entry.objective,
          vulnerabilityClass: entry.vulnerabilityClass,
          authenticationInfo: entry.authInfo,
        };

        // Match by vulnerability class slug in filename + same target
        const vulnSlug = entry.vulnerabilityClass.toLowerCase().replace(/\s+/g, "-");
        const existingIndex = subagents.findIndex(
          (s) =>
            s.type === "pentest" &&
            s.id.includes(`-${vulnSlug}-`) &&
            s.target === entry.target
        );

        if (existingIndex >= 0) {
          // File exists but manifest says running → interrupted after partial save
          // Convert the "completed" entry to "paused" with resumeInfo
          subagents[existingIndex] = {
            ...subagents[existingIndex],
            status: "paused",
            resumeInfo,
          };
        } else {
          // No file — try to load any partial messages from subagent files
          let messages: UIMessage[] = [];
          const subagentsPath = join(rootPath, "subagents");
          if (existsSync(subagentsPath)) {
            try {
              const files = readdirSync(subagentsPath).filter((f) =>
                f.endsWith(".json")
              );
              const matchingFile = files.find((f) => {
                if (vulnSlug && f.includes(vulnSlug)) return true;
                return false;
              });
              if (matchingFile) {
                const data = JSON.parse(
                  readFileSync(join(subagentsPath, matchingFile), "utf-8")
                ) as SavedSubagentData;
                messages = convertMessagesToUI(
                  data.messages,
                  new Date(entry.spawnedAt)
                );
              }
            } catch {
              // Ignore errors loading partial messages
            }
          }

          // Create a paused entry
          subagents.push({
            id: entry.id,
            name: entry.name,
            type: "pentest",
            target: entry.target,
            messages,
            createdAt: new Date(entry.spawnedAt),
            status: "paused",
            resumeInfo,
          });
        }
      }
    } catch (e) {
      console.error("Failed to load agent manifest:", e);
    }
  }

  // Load attack surface results
  const attackSurfaceResults = loadAttackSurfaceResults(rootPath);

  // Check for report
  const hasReportFile = hasReport(rootPath);

  // Detect interrupted discovery: no results file, no report, but discovery logs exist.
  // Assumption: each session has a unique root path, so stale logs from previous runs
  // cannot cause false positives. If attack-surface-results.json is manually deleted,
  // this will incorrectly mark the session as interrupted rather than allowing restart.
  const hasDiscoverySubagent = subagents.some(
    (s) => s.type === "attack-surface"
  );
  const interruptedDuringDiscovery =
    !attackSurfaceResults && !hasReportFile && hasDiscoverySubagent;

  // If discovery was interrupted, mark the discovery subagent as paused (not completed)
  if (interruptedDuringDiscovery) {
    for (let i = 0; i < subagents.length; i++) {
      if (subagents[i].type === "attack-surface" && subagents[i].status === "completed") {
        subagents[i] = { ...subagents[i], status: "paused" };
      }
    }
  }

  // Determine if session is complete
  const isComplete =
    hasReportFile ||
    (attackSurfaceResults?.summary?.analysisComplete === true &&
      subagents.length > 1);

  return {
    session,
    subagents,
    attackSurfaceResults,
    isComplete,
    hasReport: hasReportFile,
    interruptedDuringDiscovery,
  };
}
