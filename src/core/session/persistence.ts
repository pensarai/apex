/**
 * Session Persistence — Subagent I/O
 *
 * Single source of truth for writing AND reading subagent data.
 * Both saveSubagentData (write) and loadSubagents (read) share the
 * same path constants and filename conventions so they can never drift.
 */

import {
  appendFileSync,
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
const RESUME_LOG_FILE = "swarm-resume.log";

// ---------------------------------------------------------------------------
// Resume logging — lightweight append-only log for diagnosing resume issues
// ---------------------------------------------------------------------------

/**
 * Append a timestamped line to `{rootPath}/logs/swarm-resume.log`.
 * Safe to call from anywhere — never throws.
 */
export function resumeLog(rootPath: string, message: string): void {
  try {
    const logsDir = join(rootPath, "logs");
    if (!existsSync(logsDir)) mkdirSync(logsDir, { recursive: true });
    const logPath = join(logsDir, RESUME_LOG_FILE);
    const ts = new Date().toISOString();
    appendFileSync(logPath, `${ts} - ${message}\n`, "utf8");
  } catch {
    /* never throw from logging */
  }
}

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
  messages: SavedMessage[];
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

/**
 * Map an AI SDK message to the SavedMessage format.
 *
 * The AI SDK uses `args` for tool call parameters and `result` for tool
 * results, while the saved format uses `input` and `output` respectively.
 */
function mapToSavedMessage(msg: ModelMessage): SavedMessage {
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
 * The AI SDK schema uses `input` (not `args`) and `output` (not `result`),
 * which is exactly what mapToSavedMessage produces. So SavedMessages are
 * already valid ModelMessages — just cast them.
 */
function savedToModelMessage(saved: SavedMessage): ModelMessage {
  return saved as unknown as ModelMessage;
}

/**
 * Load raw ModelMessage[] for a given agent name from its most recent
 * subagent file. Returns an empty array if no file is found.
 */
export function loadSubagentMessages(
  session: SessionInfo,
  agentName: string,
): ModelMessage[] {
  const subagentsPath = join(session.rootPath, SUBAGENTS_DIR);
  if (!existsSync(subagentsPath)) return [];

  // Try stable filename first (new format)
  const stablePath = join(subagentsPath, `${agentName}.json`);
  if (existsSync(stablePath)) {
    try {
      const data = JSON.parse(
        readFileSync(stablePath, "utf-8"),
      ) as SavedSubagentData;
      return data.messages.map(savedToModelMessage);
    } catch {
      return [];
    }
  }

  // Fallback: scan for old timestamped files (agentName-TIMESTAMP.json)
  const files = readdirSync(subagentsPath)
    .filter((f) => f.startsWith(`${agentName}-`) && f.endsWith(".json"))
    .sort()
    .reverse();

  if (files.length === 0) return [];

  try {
    const data = JSON.parse(
      readFileSync(join(subagentsPath, files[0]), "utf-8"),
    ) as SavedSubagentData;
    return data.messages.map(savedToModelMessage);
  } catch {
    return [];
  }
}

/**
 * Save subagent data as a flat JSON file.
 *
 * Writes to `{session.rootPath}/{SUBAGENTS_DIR}/{name}.json`.
 * One file per agent, overwritten on each save. Timestamp is inside the JSON.
 */
export function saveSubagentData(
  session: SessionInfo,
  data: SubagentSaveInput,
): void {
  const subagentsDir = join(session.rootPath, SUBAGENTS_DIR);
  mkdirSync(subagentsDir, { recursive: true });

  let toolCallCount = 0;
  let stepCount = 0;
  const savedMessages: SavedMessage[] = [];

  for (const msg of data.messages) {
    if (msg.role === "assistant") {
      stepCount++;
      if (Array.isArray(msg.content)) {
        for (const part of msg.content) {
          if (part.type === "tool-call") toolCallCount++;
        }
      }
    }
    savedMessages.push(mapToSavedMessage(msg));
  }

  const now = new Date();
  const savedData: SavedSubagentData = {
    agentName: data.agentName,
    timestamp: now.toISOString(),
    target: data.target,
    objective: data.objective,
    vulnerabilityClass: data.vulnerabilityClass,
    toolCallCount,
    stepCount,
    findingsCount: data.findingsCount ?? 0,
    status: data.status,
    error: data.error,
    messages: savedMessages,
  };

  const filename = `${data.agentName}.json`;
  writeFileSync(
    join(subagentsDir, filename),
    JSON.stringify(savedData, null, 2),
  );

  resumeLog(
    session.rootPath,
    `[saveSubagentData] ${data.agentName}: status=${data.status}, toolCalls=${toolCallCount}, steps=${stepCount}, findings=${data.findingsCount ?? 0}, error=${data.error ?? "none"}, file=${filename}`,
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
 *
 * Completed entries (preserved from a previous run) are left untouched.
 */
export function finalizeManifest(
  session: SessionInfo,
  entries: AgentManifestEntry[],
  results: (unknown | null)[],
): void {
  const log = (msg: string) => resumeLog(session.rootPath, msg);
  log(
    `[finalizeManifest] Finalizing ${entries.length} entries, ${results.length} results`,
  );

  const finalManifest = entries.map((entry, i) => {
    const hasResult = results[i] != null;
    // Preserve already-completed entries (skipped agents on resume)
    if (entry.status === "completed") {
      log(
        `[finalizeManifest] ${entry.id}: PRESERVED completed (result=${hasResult ? "present" : "null"})`,
      );
      return entry;
    }
    const newStatus = hasResult ? "completed" : "failed";
    log(
      `[finalizeManifest] ${entry.id}: ${entry.status} → ${newStatus} (result=${hasResult ? "present" : "null"})`,
    );
    return {
      ...entry,
      status: newStatus as "completed" | "failed",
      completedAt: new Date().toISOString(),
    };
  });
  writeAgentManifest(session, finalManifest);
}

/**
 * Return the set of pentest agent IDs that successfully completed.
 *
 * Only truly completed agents are skipped on resume. Failed/aborted agents
 * are retried so the user doesn't have to start a new session.
 *
 * Checks the manifest first, then does a belt-and-suspenders scan of subagent
 * files so we catch agents that finished but whose manifest entry was lost.
 */
export function getCompletedAgentIds(session: SessionInfo): Set<string> {
  const ids = new Set<string>();
  const log = (msg: string) => resumeLog(session.rootPath, msg);

  log("[getCompletedAgentIds] START");

  // Manifest is the primary source
  const manifest = readAgentManifest(session);
  log(
    `[getCompletedAgentIds] Manifest has ${manifest.length} entries: ${manifest.map((e) => `${e.id}=${e.status}`).join(", ") || "(empty)"}`,
  );
  for (const entry of manifest) {
    // Only track pentest-agent-* IDs — discovery agents (attack-surface-agent)
    // should never count toward the "all done" check for the swarm phase.
    if (!entry.id.startsWith("pentest-agent-")) {
      log(
        `[getCompletedAgentIds] Manifest → SKIP non-pentest entry ${entry.id} (${entry.status})`,
      );
      continue;
    }
    if (entry.status === "completed") {
      ids.add(entry.id);
      log(
        `[getCompletedAgentIds] Manifest → skip ${entry.id} (completed, target=${entry.target})`,
      );
    } else if (entry.status === "failed") {
      log(
        `[getCompletedAgentIds] Manifest → RETRY ${entry.id} (failed, target=${entry.target})`,
      );
    }
  }

  // Belt-and-suspenders: scan subagent files for completed status
  const subagentsPath = join(session.rootPath, SUBAGENTS_DIR);
  if (existsSync(subagentsPath)) {
    const files = readdirSync(subagentsPath).filter((f) =>
      f.endsWith(".json"),
    );
    log(
      `[getCompletedAgentIds] Found ${files.length} subagent files in ${SUBAGENTS_DIR}/`,
    );
    for (const file of files) {
      try {
        const data = JSON.parse(
          readFileSync(join(subagentsPath, file), "utf-8"),
        ) as SavedSubagentData;
        log(
          `[getCompletedAgentIds] File ${file}: agentName=${data.agentName}, status=${data.status}, toolCalls=${data.toolCallCount ?? "?"}, steps=${data.stepCount ?? "?"}, findings=${data.findingsCount ?? "?"}`,
        );
        // Only track pentest-agent-* IDs from file scan too
        if (!data.agentName.startsWith("pentest-agent-")) {
          continue;
        }
        if (data.status === "completed") {
          const wasNew = !ids.has(data.agentName);
          ids.add(data.agentName);
          if (wasNew) {
            log(
              `[getCompletedAgentIds] File scan → skip ${data.agentName} (completed) [NEW — not in manifest]`,
            );
          }
        }
      } catch {
        log(`[getCompletedAgentIds] Failed to parse file: ${file}`);
      }
    }
  } else {
    log(`[getCompletedAgentIds] No ${SUBAGENTS_DIR}/ directory found`);
  }

  log(
    `[getCompletedAgentIds] RESULT: skipSet = {${[...ids].join(", ")}} (${ids.size} agents)`,
  );
  return ids;
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

  // Current convention: pentest-agent-{N}.json (also matches old timestamped format)
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
 * Convert saved messages to UI-compatible format.
 *
 * Two-pass algorithm:
 *  1. Collect tool results by toolCallId so we can pair them with calls.
 *  2. Emit UIMessage[] with tool-call messages enriched with their results.
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
      uiMessages.push({
        role: msg.role as "user" | "assistant" | "tool",
        content: msg.content,
        createdAt,
      });
    } else if (Array.isArray(msg.content)) {
      for (const part of msg.content) {
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
        // tool-result parts are already collected in the first pass
      }
    }
  }

  return uiMessages;
}

/**
 * Convert raw AI SDK model messages to UI-compatible display format.
 *
 * Used when restoring operator state on resume: the persisted state stores
 * only model messages, and this function derives the display messages.
 */
export function convertModelMessagesToUI(
  messages: ModelMessage[],
): UIMessage[] {
  const saved = messages.map((m) => mapToSavedMessage(m));
  return convertMessagesToUI(saved, new Date());
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
  const log = (msg: string) => resumeLog(rootPath, msg);
  const subagentsPath = join(rootPath, SUBAGENTS_DIR);

  log("[loadSubagents] START");

  // --- Load files ---
  const subagents: UISubagent[] = [];
  /** Map from agentName → index in subagents[] for manifest matching */
  const agentNameIndex = new Map<string, number>();

  if (existsSync(subagentsPath)) {
    const files = readdirSync(subagentsPath).filter((f) => f.endsWith(".json"));
    log(`[loadSubagents] Found ${files.length} subagent files`);

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

        log(
          `[loadSubagents] File ${file}: agentName=${data.agentName}, fileStatus=${data.status}, resolvedStatus=${status}, msgs=${messages.length}, toolCalls=${data.toolCallCount ?? 0}, steps=${data.stepCount ?? 0}`,
        );

        const entry: UISubagent = {
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
        };

        // Deduplicate: if we already have an entry for this agentName
        // (old sessions with multiple timestamped files), replace it
        // in-place so the array has one entry per agent.
        const prevIdx = agentNameIndex.get(data.agentName);
        if (prevIdx !== undefined) {
          log(
            `[loadSubagents] Dedup agentName=${data.agentName} — replacing idx=${prevIdx} with newer file ${file}`,
          );
          subagents[prevIdx] = entry;
        } else {
          agentNameIndex.set(data.agentName, subagents.length);
          subagents.push(entry);
        }
      } catch (e) {
        log(`[loadSubagents] ERROR loading file ${file}: ${e}`);
        console.error(`Failed to load subagent file ${file}:`, e);
      }
    }
  } else {
    log(`[loadSubagents] No ${SUBAGENTS_DIR}/ directory`);
  }

  // --- Merge with manifest ---
  const manifestPath = join(rootPath, MANIFEST_FILE);
  if (existsSync(manifestPath)) {
    try {
      const manifest: AgentManifestEntry[] = JSON.parse(
        readFileSync(manifestPath, "utf-8"),
      );
      log(
        `[loadSubagents] Manifest has ${manifest.length} entries: ${manifest.map((e) => `${e.id}=${e.status}`).join(", ")}`,
      );

      for (const entry of manifest) {
        if (entry.status !== "running") {
          log(
            `[loadSubagents] Manifest ${entry.id}: status=${entry.status}, skipping merge (not running)`,
          );
          continue;
        }

        const resumeInfo: ResumeInfo = {
          target: entry.target,
          objective: entry.objective,
          vulnerabilityClass: entry.vulnerabilityClass,
          authenticationInfo: entry.authInfo as AuthenticationInfo | undefined,
        };

        // Match by agentName === manifest entry.id (both are "pentest-agent-{N}")
        const existingIndex = agentNameIndex.get(entry.id);

        if (existingIndex !== undefined) {
          const fileStatus = subagents[existingIndex].status;
          // File exists but manifest says running → interrupted after partial save
          log(
            `[loadSubagents] Manifest ${entry.id}: running in manifest, file has status=${fileStatus}, msgs=${subagents[existingIndex].messages.length} → overriding to "paused"`,
          );
          subagents[existingIndex] = {
            ...subagents[existingIndex],
            status: "paused",
            resumeInfo,
          };
        } else {
          // No file for this running entry — create a paused stub
          log(
            `[loadSubagents] Manifest ${entry.id}: running in manifest, NO file found → creating paused stub`,
          );
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
      log(`[loadSubagents] ERROR loading manifest: ${e}`);
      console.error("Failed to load agent manifest:", e);
    }
  } else {
    log("[loadSubagents] No manifest file found");
  }

  log(
    `[loadSubagents] RESULT: ${subagents.length} subagents: ${subagents.map((s) => `${s.id}(${s.status})`).join(", ")}`,
  );
  return subagents;
}
