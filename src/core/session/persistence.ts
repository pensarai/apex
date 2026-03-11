/**
 * Session Persistence — Subagent I/O
 *
 * Single source of truth for writing AND reading subagent data.
 * Both saveSubagentData (write) and loadSubagents (read) share the
 * same path constants and filename conventions so they can never drift.
 */

import {
  existsSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  readdirSync,
} from "fs";
import { join } from "path";
import type { SessionInfo } from "./index";
export type { SessionInfo };
import type { AuthenticationInfo } from "./types";
import type { ModelMessage } from "ai";

// ---------------------------------------------------------------------------
// Shared path constants — used by both writer and reader
// ---------------------------------------------------------------------------

const SUBAGENTS_DIR = "subagents";
const MANIFEST_FILE = "agent-manifest.json";

// ---------------------------------------------------------------------------
// Types (previously in loader.ts — canonical home is now here)
// ---------------------------------------------------------------------------

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
  messages: ModelMessage[];
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
  result?: unknown;
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

// ---------------------------------------------------------------------------
// Subagent data persistence (write)
// ---------------------------------------------------------------------------

export interface SubagentSaveInput {
  agentName: string;
  target: string;
  objective?: string;
  vulnerabilityClass?: string;
  status: string;
  error?: string;
  findingsCount?: number;
  /** Raw AI SDK messages from onStepFinish (e.response.messages) */
  messages: ModelMessage[];
}

export function loadSubagentMessages(
  session: SessionInfo,
  agentName: string,
): ModelMessage[] {
  const filePath = join(session.rootPath, SUBAGENTS_DIR, `${agentName}.json`);
  if (!existsSync(filePath)) return [];
  try {
    const data = JSON.parse(
      readFileSync(filePath, "utf-8"),
    ) as SavedSubagentData;
    return data.messages;
  } catch {
    return [];
  }
}

/** Writes to `{session.rootPath}/{SUBAGENTS_DIR}/{name}.json`. */
export function saveSubagentData(
  session: SessionInfo,
  data: SubagentSaveInput,
): void {
  const subagentsDir = join(session.rootPath, SUBAGENTS_DIR);
  mkdirSync(subagentsDir, { recursive: true });

  let toolCallCount = 0;
  let stepCount = 0;

  for (const msg of data.messages) {
    if (msg.role === "assistant") {
      stepCount++;
      if (Array.isArray(msg.content)) {
        for (const part of msg.content) {
          if (part.type === "tool-call") toolCallCount++;
        }
      }
    }
  }

  const savedData: SavedSubagentData = {
    agentName: data.agentName,
    timestamp: new Date().toISOString(),
    target: data.target,
    objective: data.objective,
    vulnerabilityClass: data.vulnerabilityClass,
    toolCallCount,
    stepCount,
    findingsCount: data.findingsCount ?? 0,
    status: data.status,
    error: data.error,
    messages: data.messages,
  };

  writeFileSync(
    join(subagentsDir, `${data.agentName}.json`),
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
  const manifestPath = join(session.rootPath, MANIFEST_FILE);
  writeFileSync(manifestPath, JSON.stringify(entries, null, 2));
}

/**
 * Read the current agent manifest, or return empty array if none exists.
 */
export function readAgentManifest(session: SessionInfo): AgentManifestEntry[] {
  const manifestPath = join(session.rootPath, MANIFEST_FILE);
  if (!existsSync(manifestPath)) return [];
  try {
    return JSON.parse(readFileSync(manifestPath, "utf-8"));
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Swarm orchestration helpers
// ---------------------------------------------------------------------------

/** A normalized target for the pentest swarm */
export interface SwarmTarget {
  name?: string;
  target: string;
  objectives: string[];
}

/**
 * Build initial manifest entries for a swarm of pentest agents.
 * All entries start with status "running".
 */
export function buildManifestEntries(
  targets: SwarmTarget[],
): AgentManifestEntry[] {
  return targets.map((t, i) => ({
    id: `pentest-agent-${i + 1}`,
    name: `Pentest Agent ${i + 1}`,
    target: t.target,
    vulnerabilityClass: t.objectives[0] || "general",
    objective: t.objectives.join("; "),
    status: "running" as const,
    spawnedAt: new Date().toISOString(),
  }));
}

/**
 * Rewrite the agent manifest with final statuses.
 * Uses index-based matching (not target-based) to correctly handle
 * duplicate targets.
 */
export function finalizeManifest(
  session: SessionInfo,
  entries: AgentManifestEntry[],
  results: (unknown | null)[],
): void {
  const finalManifest = entries.map((entry, i) => {
    if (entry.status === "completed") return entry;
    return {
      ...entry,
      status: (results[i] != null ? "completed" : "failed") as
        | "completed"
        | "failed",
      completedAt: new Date().toISOString(),
    };
  });
  writeAgentManifest(session, finalManifest);
}

/**
 * Atomically update a single agent's status in the manifest.
 * Safe under Node.js concurrency — readFileSync + writeFileSync
 * runs synchronously without event loop interleaving.
 */
export function updateManifestEntryStatus(
  session: SessionInfo,
  agentId: string,
  status: "completed" | "failed",
): void {
  const manifest = readAgentManifest(session);
  const updated = manifest.map((e) =>
    e.id === agentId
      ? { ...e, status, completedAt: new Date().toISOString() }
      : e,
  );
  writeAgentManifest(session, updated);
}

export function getCompletedAgentIds(session: SessionInfo): Set<string> {
  const manifest = readAgentManifest(session);
  return new Set(
    manifest
      .filter(
        (e) => e.id.startsWith("pentest-agent-") && e.status === "completed",
      )
      .map((e) => e.id),
  );
}

// ---------------------------------------------------------------------------
// Subagent data loading (read) — previously in loader.ts
// ---------------------------------------------------------------------------

/**
 * Parse a subagent filename to extract agent type and display name.
 *
 * Handles every naming convention the writer has ever used:
 *  - "attack-surface-agent-..."  → attack-surface
 *  - "pentest-agent-3-..."       → pentest, "Pentest Agent 3"
 *  - "vuln-test-sqli-..."        → pentest (back-compat)
 *  - "orchestrator-..."          → skipped upstream
 *  - fallback                    → pentest
 */
function parseSubagentFilename(filename: string): {
  agentType: "attack-surface" | "pentest";
  name: string;
} {
  if (filename.startsWith("attack-surface-agent")) {
    return { agentType: "attack-surface", name: "Attack Surface Discovery" };
  }

  const pentestMatch = filename.match(/^pentest-agent-(\d+)/);
  if (pentestMatch) {
    return {
      agentType: "pentest",
      name: `Pentest Agent ${pentestMatch[1]}`,
    };
  }

  // Legacy convention: vuln-test-{vulnClass}-...
  if (filename.startsWith("vuln-test-")) {
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
 * Two-pass: collect tool results by toolCallId, then emit UIMessage[]
 * with tool-call messages enriched with their results.
 */
function convertMessagesToUI(
  messages: ModelMessage[],
  baseTime: Date,
): UIMessage[] {
  const uiMessages: UIMessage[] = [];
  let messageIndex = 0;

  const toolResults = new Map<string, unknown>();
  for (const msg of messages) {
    if (Array.isArray(msg.content)) {
      for (const part of msg.content as MessageContentPart[]) {
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
      uiMessages.push({
        role: msg.role as "user" | "assistant" | "tool",
        content: msg.content,
        createdAt,
      });
    } else if (Array.isArray(msg.content)) {
      for (const part of msg.content as MessageContentPart[]) {
        if (part.type === "text" && part.text) {
          uiMessages.push({
            role: "assistant",
            content: part.text,
            createdAt,
          });
        } else if (part.type === "tool-call") {
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
      }
    }
  }

  return uiMessages;
}

export function convertModelMessagesToUI(
  messages: ModelMessage[],
): UIMessage[] {
  return convertMessagesToUI(messages, new Date());
}

/**
 * Load all subagent data from disk and merge with the agent manifest.
 *
 * This is the single reader for subagent state. It:
 *  1. Reads all .json files from {rootPath}/{SUBAGENTS_DIR}/
 *  2. Reads the agent manifest from {rootPath}/{MANIFEST_FILE}
 *  3. Matches manifest entries to loaded files by agentName === entry.id
 *  4. Marks matched "running" manifest entries as "paused"
 *  5. Creates paused stubs for unmatched "running" manifest entries
 */
export function loadSubagents(rootPath: string): UISubagent[] {
  const subagentsPath = join(rootPath, SUBAGENTS_DIR);

  // --- Load files ---
  const subagents: UISubagent[] = [];
  /** Map from agentName → index in subagents[] for manifest matching */
  const agentNameIndex = new Map<string, number>();

  if (existsSync(subagentsPath)) {
    const files = readdirSync(subagentsPath).filter((f) => f.endsWith(".json"));

    files.sort();

    for (const file of files) {
      // Skip orchestrator summary files — not real subagents
      if (file.startsWith("orchestrator-")) continue;

      try {
        const filePath = join(subagentsPath, file);
        const data = JSON.parse(
          readFileSync(filePath, "utf-8"),
        ) as SavedSubagentData;

        const { agentType, name } = parseSubagentFilename(file);
        const timestamp = new Date(data.timestamp);
        const messages = convertMessagesToUI(data.messages, timestamp);

        let status: "pending" | "completed" | "failed" | "canceled" =
          "completed";
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

        agentNameIndex.set(data.agentName, subagents.length);
        subagents.push({
          id: data.agentName,
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
  }

  // --- Merge with manifest ---
  const manifestPath = join(rootPath, MANIFEST_FILE);
  if (existsSync(manifestPath)) {
    try {
      const manifest: AgentManifestEntry[] = JSON.parse(
        readFileSync(manifestPath, "utf-8"),
      );
      for (const entry of manifest) {
        if (entry.status !== "running") continue;

        const resumeInfo: ResumeInfo = {
          target: entry.target,
          objective: entry.objective,
          vulnerabilityClass: entry.vulnerabilityClass,
          authenticationInfo: entry.authInfo as AuthenticationInfo | undefined,
        };

        // Match by agentName === manifest entry.id (both are "pentest-agent-{N}")
        const existingIndex = agentNameIndex.get(entry.id);

        if (existingIndex !== undefined) {
          subagents[existingIndex] = {
            ...subagents[existingIndex],
            status: "paused",
            resumeInfo,
          };
        } else {
          subagents.push({
            id: entry.id,
            name: entry.name,
            type: "pentest",
            target: entry.target,
            messages: [],
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

  return subagents;
}
