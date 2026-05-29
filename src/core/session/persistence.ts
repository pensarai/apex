/**
 * Session Persistence — Subagent I/O
 *
 * Single source of truth for writing AND reading subagent data.
 * Both saveSubagentData (write) and loadSubagents (read) share the
 * same path constants and filename conventions so they can never drift.
 *
 * Directory key — every subagent is stored under
 * `{rootPath}/subagents/{key}/` where `key` is the subagent's identity. For
 * subagents spawned via `spawn_pentest_agent` the key IS the child's session
 * id (`ses_…`), minted before spawn. The swarm path (`spawn_pentest_swarm`)
 * still uses stable slot ids (`pentest-agent-N`) so its index-based manifest
 * resume logic keeps working; this layer is agnostic to the key's shape.
 */

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "fs";
import { join } from "path";
import { getSessionRoot, normalizeMessages, type SessionInfo } from "./index";

export type { SessionInfo };

import type { ModelMessage } from "ai";
import type { SessionID } from "../id/id";
import type { AuthenticationInfo } from "./types";

// ---------------------------------------------------------------------------
// Shared path constants — used by both writer and reader
// ---------------------------------------------------------------------------

const SUBAGENTS_DIR = "subagents";
const MANIFEST_FILE = "agent-manifest.json";

// ---------------------------------------------------------------------------
// Types (previously in loader.ts — canonical home is now here)
// ---------------------------------------------------------------------------

/**
 * Saved subagent data format
 */
interface SavedSubagentData {
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
  messages?: ModelMessage[];
  /** System prompt used for this agent run (for training data export) */
  systemPrompt?: string;
  /** Initial user prompt / task assignment (for training data export) */
  userPrompt?: string;
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
  status?: "pending" | "completed" | "error";
}

/**
 * Information needed to resume a paused agent
 */
interface ResumeInfo {
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
  /** System prompt used for this agent (for training data export) */
  systemPrompt?: string;
  /** Initial user prompt / task assignment (for training data export) */
  userPrompt?: string;
}

/**
 * Read a subagent's persisted messages by directory key.
 *
 * `key` is the subagent's identity directory under `subagents/` — a session
 * id (`ses_…`) for `spawn_pentest_agent` workers, or a slot id
 * (`pentest-agent-N`) for the swarm.
 */
export function loadSubagentMessages(
  session: SessionInfo,
  key: string,
): ModelMessage[] {
  // Primary: base class step persistence (written incrementally, survives aborts)
  const stepPath = join(session.rootPath, SUBAGENTS_DIR, key, "messages.json");
  if (existsSync(stepPath)) {
    try {
      return JSON.parse(readFileSync(stepPath, "utf-8")) as ModelMessage[];
    } catch {
      // Fall through to snapshot
    }
  }
  // Fallback: old snapshot format (pre-split sessions)
  const snapshotPath = join(session.rootPath, SUBAGENTS_DIR, `${key}.json`);
  if (!existsSync(snapshotPath)) return [];
  try {
    const data = JSON.parse(
      readFileSync(snapshotPath, "utf-8"),
    ) as SavedSubagentData;
    return data.messages ?? [];
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
    systemPrompt: data.systemPrompt,
    userPrompt: data.userPrompt,
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
  /**
   * Directory key / identity for this subagent. Equal to {@link sessionId}
   * when the subagent's identity is a minted session id (`ses_…`); for the
   * swarm path this is a stable slot id (`pentest-agent-N`).
   */
  id: string;
  /**
   * The subagent's session id (`ses_…`) when it has one. Mirrors {@link id}
   * for session-keyed subagents; carried explicitly so downstream consumers
   * can route by session without re-parsing the directory key.
   */
  sessionId?: string;
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
 * Parse a subagent filename (or directory name) to extract agent type and display name.
 *
 * Handles every naming convention the writer has ever used:
 *  - "attack-surface-agent-..."      → attack-surface
 *  - "whitebox-apps-discovery"       → attack-surface
 *  - "pages-<app>" / "apiEndpoints-<app>" / "cloudResourceEndpoints-<app>" → attack-surface (whitebox discovery)
 *  - "threat-model-<app>-<endpoint>" → attack-surface (threat model)
 *  - "pentest-agent-3-..."           → pentest, "Pentest Agent 3"
 *  - "vuln-test-sqli-..."            → pentest (back-compat)
 *  - "orchestrator-..."              → skipped upstream
 *  - fallback                        → pentest
 */
function parseSubagentFilename(filename: string): {
  agentType: UISubagent["type"];
  name: string;
} {
  if (filename.startsWith("attack-surface-agent")) {
    return { agentType: "attack-surface", name: "Attack Surface Discovery" };
  }

  if (filename === "whitebox-apps-discovery") {
    return { agentType: "pentest", name: "Whitebox Apps Discovery" };
  }

  if (filename === "whitebox-incremental") {
    return { agentType: "pentest", name: "Incremental Recon" };
  }

  if (filename.startsWith("pages-")) {
    const appName = filename.replace("pages-", "");
    return { agentType: "pentest", name: `Pages: ${appName}` };
  }

  if (filename.startsWith("apiEndpoints-")) {
    const appName = filename.replace("apiEndpoints-", "");
    return { agentType: "pentest", name: `API Endpoints: ${appName}` };
  }

  if (filename.startsWith("cloudResourceEndpoints-")) {
    const appName = filename.replace("cloudResourceEndpoints-", "");
    return { agentType: "pentest", name: `Cloud Resources: ${appName}` };
  }

  if (filename.startsWith("threat-model-")) {
    // Writer joins app + endpoint with "-" but sanitize preserves dashes,
    // so we can't split reliably. Show the whole trailing portion.
    const rest = filename.replace("threat-model-", "");
    return { agentType: "pentest", name: `Threat Model: ${rest}` };
  }

  const pentestMatch = filename.match(/^pentest-agent-(\d+)/);
  if (pentestMatch) {
    return {
      agentType: "pentest",
      name: `Pentest Agent ${pentestMatch[1]}`,
    };
  }

  const codingMatch = filename.match(/^coding-agent-(\d+)/);
  if (codingMatch) {
    return {
      agentType: "pentest",
      name: `Coding Agent ${codingMatch[1]}`,
    };
  }

  if (filename === "auth-agent") {
    return { agentType: "pentest", name: "Auth Agent" };
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

  // Session-id-keyed subagent (spawn_pentest_agent worker). The
  // human-readable label lives on the `subagent-spawn` bus event / manifest;
  // when loading from disk alone we don't have it, so fall back to a generic
  // pentest worker label rather than surfacing the raw `ses_…` id.
  if (filename.startsWith("ses_")) {
    return { agentType: "pentest", name: "Pentest Worker" };
  }

  return { agentType: "pentest", name: filename.split("-")[0] || "Unknown" };
}

/**
 * AI SDK v6 persists tool outputs on `response.messages` (e.g. `messages.json`)
 * as `{ type: "json", value }` or `{ type: "text", value }`. Streaming
 * `tool-result` events use the raw `execute()` return value. Normalize here so
 * resumed operator sessions render the same summaries as a live run.
 */
function unwrapAiSdkToolOutput(output: unknown): unknown {
  if (output === null || typeof output !== "object") return output;
  const o = output as Record<string, unknown>;
  switch (o.type) {
    case "json":
    case "error-json":
      if ("value" in o) return o.value;
      break;
    case "text":
    case "error-text":
      if (typeof o.value === "string") return o.value;
      break;
    case "execution-denied":
      return o.reason ?? "Tool execution denied";
  }
  return output;
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
      for (const part of msg.content) {
        if (part.type === "tool-result" && part.toolCallId) {
          toolResults.set(part.toolCallId, unwrapAiSdkToolOutput(part.output));
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
          const input = part.input as Record<string, unknown> | undefined;
          const toolDescription =
            typeof input?.toolCallDescription === "string"
              ? input.toolCallDescription
              : part.toolName || "tool";
          const hasResult = part.toolCallId
            ? toolResults.has(part.toolCallId)
            : false;
          const result = part.toolCallId
            ? toolResults.get(part.toolCallId)
            : undefined;
          const resultText =
            typeof result === "string"
              ? result
              : result != null &&
                  typeof result === "object" &&
                  "value" in (result as Record<string, unknown>) &&
                  typeof (result as Record<string, unknown>).value === "string"
                ? ((result as Record<string, unknown>).value as string)
                : undefined;
          const cancelled =
            typeof resultText === "string" &&
            resultText.toLowerCase().includes("cancelled");
          // A tool-call with no matching tool-result means the agent was
          // interrupted mid-step; surface that instead of silently falling
          // through to "completed".
          const interrupted = !hasResult;
          uiMessages.push({
            role: "tool",
            content: toolDescription,
            createdAt,
            toolCallId: part.toolCallId,
            toolName: part.toolName,
            args: input,
            result: interrupted ? "Interrupted" : result,
            status: cancelled || interrupted ? "error" : "completed",
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
 *  2. Discovers subdirectories with messages.json (no snapshot .json)
 *  3. Reads the agent manifest from {rootPath}/{MANIFEST_FILE}
 *  4. Matches manifest entries to loaded files by agentName === entry.id
 *  5. Marks matched "running" manifest entries as "paused"
 *  6. Creates paused stubs for unmatched "running" manifest entries
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

        // Read messages from base class step persistence (primary),
        // fall back to snapshot's messages field (old sessions)
        const agentName = data.agentName;
        const stepPath = join(subagentsPath, agentName, "messages.json");
        let messages: UIMessage[];
        if (existsSync(stepPath)) {
          try {
            const raw = JSON.parse(
              readFileSync(stepPath, "utf-8"),
            ) as ModelMessage[];
            messages = convertMessagesToUI(raw, timestamp);
          } catch {
            messages = convertMessagesToUI(data.messages ?? [], timestamp);
          }
        } else {
          messages = convertMessagesToUI(data.messages ?? [], timestamp);
        }

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

    // Some agents (threat model, whitebox discovery, coding agents) only
    // persist messages.json via the base class but never call
    // saveSubagentData(). Scan for subdirectories with messages.json
    // that have no matching top-level snapshot .json file.
    const entries = readdirSync(subagentsPath, { withFileTypes: true });
    for (const dirent of entries) {
      if (!dirent.isDirectory()) continue;
      const entry = dirent.name;
      if (agentNameIndex.has(entry)) continue;
      if (entry.endsWith("-tasks") || entry.endsWith("-plan")) continue;

      const messagesPath = join(subagentsPath, entry, "messages.json");
      try {
        const raw = JSON.parse(
          readFileSync(messagesPath, "utf-8"),
        ) as ModelMessage[];
        if (!Array.isArray(raw) || raw.length === 0) continue;

        const { agentType, name } = parseSubagentFilename(entry);
        const timestamp = statSync(messagesPath).mtime;
        const messages = convertMessagesToUI(raw, timestamp);

        agentNameIndex.set(entry, subagents.length);
        subagents.push({
          id: entry,
          name,
          type: agentType,
          target: "Unknown",
          messages,
          createdAt: timestamp,
          status: "completed",
        });
      } catch {
        // Skip directories without a readable messages.json
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

// ---------------------------------------------------------------------------
// Console rehydration — rebuild on-disk session state from the Console DB
// ---------------------------------------------------------------------------
//
// Apex must stay standalone: it cannot import any `@console/*` package. The
// Console session tree is therefore supplied through an INJECTED `fetchTree`
// callback (the parent `runApexAgent` passes the agent-SDK fetcher). This file
// only knows the *shape* of the data, declared inline below.

/** A persisted agent message row (Console `agent_messages`). */
export interface ConsoleMessageRow {
  id: string;
  sessionId: string;
  role: "user" | "assistant" | "system";
  sequence: number;
  stepSeq: number | null;
  data: unknown;
  createdAt: string | Date;
}

/** A persisted agent part row (Console `agent_parts`). */
export interface ConsolePartRow {
  id: string;
  messageId: string;
  sessionId: string;
  index: number;
  type: "text" | "tool" | "file" | "subagent_ref";
  toolCallId: string | null;
  s3Key: string | null;
  data: unknown;
  createdAt: string | Date;
}

/** One session node (root or descendant) of a Console session tree. */
export interface ConsoleSessionNode {
  session: {
    id: string;
    agentType: string;
    parentSessionId: string | null;
    status: string;
    metadata?: unknown;
  };
  messages: ConsoleMessageRow[];
  parts: ConsolePartRow[];
}

/**
 * The full session tree returned by `agentApi.execution.getSessionTree`.
 * Mirrors the Console shape without importing it.
 */
export interface ConsoleSessionTree extends ConsoleSessionNode {
  descendants: ConsoleSessionNode[];
}

/** Injected fetcher — resolves a Console session tree by session id. */
export type FetchConsoleTree = (id: string) => Promise<ConsoleSessionTree>;

/** Result of rehydration: the on-disk root plus in-memory model messages. */
export interface RehydrateResult {
  rootPath: string;
  /** Root-session model messages, ready for the agent constructor. */
  messages: ModelMessage[];
  /** childSessionId → that subagent's model messages. */
  subagentMessages: Map<string, ModelMessage[]>;
}

// --- Part-data shapes (mirror @pensar/core executionTypes, declared inline) --

interface TextPartData {
  text: string;
  preview?: string;
}
type ToolOutput = string | { s3Key: string; preview: string };
interface ToolStatePending {
  status: "pending" | "running";
  input: Record<string, unknown>;
}
interface ToolStateCompleted {
  status: "completed";
  input: Record<string, unknown>;
  output: ToolOutput;
}
interface ToolStateError {
  status: "error";
  input: Record<string, unknown>;
  errorMessage: string;
}
type ToolState = ToolStatePending | ToolStateCompleted | ToolStateError;
interface ToolPartData {
  toolCallId: string;
  tool: string;
  state: ToolState;
}

/** Resolve a tool output blob to the AI-SDK structured tool-result `output`. */
function toolOutputToModelOutput(output: ToolOutput): {
  type: "text";
  value: string;
} {
  if (typeof output === "string") return { type: "text", value: output };
  // S3-offloaded: inline previews are enough for resume context. Fetching the
  // full blob from S3 is out of scope here.
  // TODO(A2): a tool that re-reads its own prior full output would need the S3
  // blob; resume only needs the preview for conversational context.
  return { type: "text", value: output.preview };
}

/**
 * Convert one Console message + its ordered parts into AI-SDK `ModelMessage`s.
 *
 * A single Console assistant message can expand into TWO model messages: the
 * assistant turn (text + tool-call parts) followed by a `tool` message holding
 * the matching tool-results. `subagent_ref` parts are spawn markers only — the
 * child transcript lives in its own `subagents/{childSessionId}/messages.json`,
 * never inlined here.
 */
function consoleMessageToModelMessages(
  message: ConsoleMessageRow,
  parts: ConsolePartRow[],
): ModelMessage[] {
  const ordered = [...parts].sort((a, b) => a.index - b.index);

  // user / system → plain text content (concatenate text parts).
  if (message.role === "user" || message.role === "system") {
    const text = ordered
      .filter((p) => p.type === "text")
      .map((p) => (p.data as TextPartData | null)?.text ?? "")
      .join("");
    return [{ role: message.role, content: text } as ModelMessage];
  }

  // assistant → assistant content array (text + tool-call) plus a trailing
  // tool message for completed tool-results.
  const assistantContent: Array<Record<string, unknown>> = [];
  const toolResults: Array<Record<string, unknown>> = [];

  for (const part of ordered) {
    if (part.type === "text") {
      const text = (part.data as TextPartData | null)?.text ?? "";
      if (text) assistantContent.push({ type: "text", text });
    } else if (part.type === "tool") {
      const tool = part.data as ToolPartData | null;
      if (!tool) continue;
      assistantContent.push({
        type: "tool-call",
        toolCallId: tool.toolCallId,
        toolName: tool.tool,
        input: tool.state.input ?? {},
      });
      if (tool.state.status === "completed") {
        toolResults.push({
          type: "tool-result",
          toolCallId: tool.toolCallId,
          toolName: tool.tool,
          output: toolOutputToModelOutput(tool.state.output),
        });
      } else if (tool.state.status === "error") {
        toolResults.push({
          type: "tool-result",
          toolCallId: tool.toolCallId,
          toolName: tool.tool,
          output: { type: "text", value: `tool failed: ${tool.state.errorMessage}` },
        });
      }
      // pending/running tool-calls are left without a tool-result here; the
      // open-tool-call repair pass below synthesizes one so the in-memory
      // message list is valid for the agent constructor.
    }
    // `file` and `subagent_ref` parts are not inlined into model messages.
  }

  const out: ModelMessage[] = [];
  if (assistantContent.length > 0) {
    out.push({ role: "assistant", content: assistantContent } as ModelMessage);
  }
  if (toolResults.length > 0) {
    out.push({ role: "tool", content: toolResults } as ModelMessage);
  }
  return out;
}

/** Convert a whole Console session node (root or descendant) to ModelMessages. */
function nodeToModelMessages(node: ConsoleSessionNode): ModelMessage[] {
  const partsByMessage = new Map<string, ConsolePartRow[]>();
  for (const part of node.parts) {
    const arr = partsByMessage.get(part.messageId);
    if (arr) arr.push(part);
    else partsByMessage.set(part.messageId, [part]);
  }

  const messages = [...node.messages].sort((a, b) => a.sequence - b.sequence);
  const out: ModelMessage[] = [];
  for (const message of messages) {
    out.push(
      ...consoleMessageToModelMessages(
        message,
        partsByMessage.get(message.id) ?? [],
      ),
    );
  }
  return out;
}

/**
 * Repair orphan (open) tool-calls left by a mid-step crash.
 *
 * A trailing assistant `tool-call` with no matching `tool` message means the
 * process died after issuing the call but before persisting a result. The DB
 * row stays `running` (monotonicity invariant); this repair ONLY mutates the
 * in-memory message list handed to the agent constructor, so the conversation
 * is well-formed (every tool-call has a tool-result).
 *
 * For each unmatched tool-call we append a synthesized `tool` message with
 * `output: { type: "text", value: "tool failed: process terminated" }`.
 */
export function repairOrphanToolCalls(
  messages: ModelMessage[],
): ModelMessage[] {
  // Collect every toolCallId that already has a tool-result.
  const resolved = new Set<string>();
  for (const msg of messages) {
    if (msg.role !== "tool" || !Array.isArray(msg.content)) continue;
    for (const part of msg.content as Array<Record<string, unknown>>) {
      if (part.type === "tool-result" && typeof part.toolCallId === "string") {
        resolved.add(part.toolCallId);
      }
    }
  }

  const result: ModelMessage[] = [];
  for (const msg of messages) {
    result.push(msg);
    if (msg.role !== "assistant" || !Array.isArray(msg.content)) continue;

    const orphanResults: Array<Record<string, unknown>> = [];
    for (const part of msg.content as Array<Record<string, unknown>>) {
      if (
        part.type === "tool-call" &&
        typeof part.toolCallId === "string" &&
        !resolved.has(part.toolCallId)
      ) {
        resolved.add(part.toolCallId);
        orphanResults.push({
          type: "tool-result",
          toolCallId: part.toolCallId,
          toolName: part.toolName,
          output: { type: "text", value: "tool failed: process terminated" },
        });
      }
    }
    if (orphanResults.length > 0) {
      result.push({ role: "tool", content: orphanResults } as ModelMessage);
    }
  }
  return result;
}

/** Run a message list through the resume normalizer + orphan-tool repair. */
function finalizeResumeMessages(messages: ModelMessage[]): ModelMessage[] {
  return normalizeMessages(repairOrphanToolCalls(messages));
}

/** Atomic JSON write: write to a temp sibling then rename into place. */
function atomicWriteJson(filePath: string, value: unknown): void {
  mkdirSync(join(filePath, ".."), { recursive: true });
  const tmp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmp, JSON.stringify(value, null, 2), "utf-8");
  renameSync(tmp, filePath);
}

/**
 * Rebuild a session's on-disk state from an already-fetched Console session
 * tree. Prefer this over {@link rehydrateFromConsole} when the caller already
 * holds the tree (avoids a double fetch).
 *
 * Writes (atomically):
 *  - `~/.pensar/sessions/{id}/session.json` — minimal metadata stub
 *  - `~/.pensar/sessions/{id}/messages.json` — root model messages
 *  - `~/.pensar/sessions/{id}/subagents/{childSessionId}/messages.json` per
 *    descendant
 *
 * Returns the in-memory root `messages` and a `subagentMessages` map for the
 * constructor. Open tool-calls are repaired in the returned in-memory messages
 * only (the DB rows are untouched).
 */
export function rehydrateFromConsoleTree(
  sessionId: SessionID,
  tree: ConsoleSessionTree,
): RehydrateResult {
  const rootPath = getSessionRoot(sessionId);

  // Root.
  const rootMessages = finalizeResumeMessages(nodeToModelMessages(tree));

  // session.json stub — enough for downstream readers; the live session.json
  // written by sessions.create() already carries full config, so only refresh
  // it if it does not already exist (do not clobber richer metadata).
  const sessionJsonPath = join(rootPath, "session.json");
  if (!existsSync(sessionJsonPath)) {
    atomicWriteJson(sessionJsonPath, {
      id: tree.session.id,
      agentType: tree.session.agentType,
      parentSessionId: tree.session.parentSessionId,
      status: tree.session.status,
      metadata: tree.session.metadata ?? null,
    });
  }

  atomicWriteJson(join(rootPath, "messages.json"), rootMessages);

  // Descendants → subagents/{childSessionId}/messages.json.
  const subagentMessages = new Map<string, ModelMessage[]>();
  for (const descendant of tree.descendants) {
    const childId = descendant.session.id;
    const childMessages = finalizeResumeMessages(
      nodeToModelMessages(descendant),
    );
    subagentMessages.set(childId, childMessages);
    atomicWriteJson(
      join(rootPath, SUBAGENTS_DIR, childId, "messages.json"),
      childMessages,
    );
  }

  return { rootPath, messages: rootMessages, subagentMessages };
}

/**
 * Fetch a Console session tree (via the injected `fetchTree`) and rebuild the
 * session's on-disk state from it. See {@link rehydrateFromConsoleTree}.
 */
export async function rehydrateFromConsole(
  sessionId: SessionID,
  fetchTree: FetchConsoleTree,
): Promise<RehydrateResult> {
  const tree = await fetchTree(sessionId);
  return rehydrateFromConsoleTree(sessionId, tree);
}
