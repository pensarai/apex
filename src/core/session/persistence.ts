/**
 * Session Persistence Utilities
 *
 * Saves subagent data and agent manifests in the format expected by the
 * session loader (loader.ts). Designed to be called from workflows and
 * tools after each agent completes or fails.
 */

import { existsSync, mkdirSync, writeFileSync, readFileSync } from "fs";
import { join } from "path";
import type { SessionInfo } from "./index";
import type {
  SavedSubagentData,
  SavedMessage,
  MessageContentPart,
} from "./loader";

// ---------------------------------------------------------------------------
// Subagent data persistence
// ---------------------------------------------------------------------------

interface SubagentSaveInput {
  agentName: string;
  target: string;
  objective?: string;
  vulnerabilityClass?: string;
  status: string;
  error?: string;
  /** Raw AI SDK messages from onStepFinish (e.response.messages) */
  messages: unknown[];
}

/**
 * Map an AI SDK message to the SavedMessage format expected by the loader.
 *
 * The AI SDK uses `args` for tool call parameters and `result` for tool
 * results, while the loader expects `input` and `output` respectively.
 */
function mapToSavedMessage(msg: unknown): SavedMessage {
  const m = msg as { role: string; content: unknown };

  if (typeof m.content === "string") {
    return { role: m.role as SavedMessage["role"], content: m.content };
  }

  if (Array.isArray(m.content)) {
    const mapped: MessageContentPart[] = m.content.map(
      (part: Record<string, unknown>) => {
        if (part.type === "tool-call") {
          return {
            type: "tool-call" as const,
            toolCallId: part.toolCallId as string,
            toolName: part.toolName as string,
            input: (part.args ?? part.input) as Record<string, unknown>,
          };
        }
        if (part.type === "tool-result") {
          return {
            type: "tool-result" as const,
            toolCallId: part.toolCallId as string,
            toolName: part.toolName as string,
            output: (part.result ?? part.output) as unknown,
          };
        }
        return {
          type: "text" as const,
          text: (part.text as string) ?? "",
        };
      },
    );
    return { role: m.role as SavedMessage["role"], content: mapped };
  }

  return { role: m.role as SavedMessage["role"], content: String(m.content) };
}

/**
 * Save subagent data in the format expected by the session loader.
 *
 * Writes a flat JSON file to `{session.rootPath}/subagents/{name}-{timestamp}.json`.
 * The loader (loadSubagents) reads all `.json` files in this directory and
 * parses them as SavedSubagentData.
 */
export function saveSubagentData(
  session: SessionInfo,
  data: SubagentSaveInput,
): void {
  const subagentsDir = join(session.rootPath, "subagents");
  if (!existsSync(subagentsDir)) {
    mkdirSync(subagentsDir, { recursive: true });
  }

  let toolCallCount = 0;
  let stepCount = 0;
  const savedMessages: SavedMessage[] = [];

  for (const msg of data.messages) {
    const m = msg as { role: string; content: unknown };
    if (m.role === "assistant") {
      stepCount++;
      if (Array.isArray(m.content)) {
        for (const part of m.content as Array<{ type: string }>) {
          if (part.type === "tool-call") toolCallCount++;
        }
      }
    }
    savedMessages.push(mapToSavedMessage(msg));
  }

  const savedData: SavedSubagentData = {
    agentName: data.agentName,
    timestamp: new Date().toISOString(),
    target: data.target,
    objective: data.objective,
    vulnerabilityClass: data.vulnerabilityClass,
    toolCallCount,
    stepCount,
    findingsCount: 0,
    status: data.status,
    error: data.error,
    messages: savedMessages,
  };

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `${data.agentName}-${ts}.json`;
  writeFileSync(
    join(subagentsDir, filename),
    JSON.stringify(savedData, null, 2),
  );
}

// ---------------------------------------------------------------------------
// Agent manifest
// ---------------------------------------------------------------------------

export interface AgentManifestEntry {
  id: string;
  name: string;
  target: string;
  vulnerabilityClass: string;
  objective: string;
  authInfo?: Record<string, unknown>;
  status: "running" | "completed" | "failed";
  spawnedAt: string;
  completedAt?: string;
}

/**
 * Write the agent manifest file.
 * The manifest tracks which agents are running/completed so the loader
 * can detect interrupted (paused) agents on resume.
 */
export function writeAgentManifest(
  session: SessionInfo,
  entries: AgentManifestEntry[],
): void {
  const manifestPath = join(session.rootPath, "agent-manifest.json");
  writeFileSync(manifestPath, JSON.stringify(entries, null, 2));
}

/**
 * Read the current agent manifest, or return empty array if none exists.
 */
export function readAgentManifest(session: SessionInfo): AgentManifestEntry[] {
  const manifestPath = join(session.rootPath, "agent-manifest.json");
  if (!existsSync(manifestPath)) return [];
  try {
    return JSON.parse(readFileSync(manifestPath, "utf-8"));
  } catch {
    return [];
  }
}
