import type { OperatorMessage } from "./contract";

export type ToolStatus =
  | "pending"
  | "running"
  | "completed"
  | "error"
  | "cancelled"
  | "unknown";
export type ToolKind =
  | "command"
  | "http"
  | "file"
  | "search"
  | "browser"
  | "finding"
  | "agent"
  | "generic";
export interface ToolPresentation {
  name: string;
  headline: string;
  description?: string;
  status: ToolStatus;
  summary?: string;
  input: unknown;
  output: unknown;
  kind: ToolKind;
}
export type TranscriptRow =
  | { kind: "message"; key: string; message: OperatorMessage }
  | { kind: "tools"; key: string; items: OperatorMessage[] };

type ToolDefinition = { name: string; kind: ToolKind; fields?: string[] };
const definitions: Record<string, ToolDefinition> = {
  execute_command: {
    name: "Run command",
    kind: "command",
    fields: ["command"],
  },
  command_job: { name: "Command job", kind: "command", fields: ["jobId"] },
  http_request: { name: "HTTP request", kind: "http", fields: ["url"] },
  read_file: { name: "Read file", kind: "file", fields: ["path", "file_path"] },
  list_files: {
    name: "List files",
    kind: "file",
    fields: ["directory", "path"],
  },
  create_file: {
    name: "Create file",
    kind: "file",
    fields: ["path", "file_path"],
  },
  write_file: {
    name: "Write file",
    kind: "file",
    fields: ["path", "file_path"],
  },
  update_file: {
    name: "Edit file",
    kind: "file",
    fields: ["path", "file_path"],
  },
  delete_file: { name: "Delete file", kind: "file", fields: ["path"] },
  apply_patch: { name: "Apply patch", kind: "file" },
  git_diff: { name: "Git diff", kind: "file", fields: ["path"] },
  git_status: { name: "Git status", kind: "file" },
  grep: { name: "Search contents", kind: "search", fields: ["pattern"] },
  glob: { name: "Find files", kind: "search", fields: ["pattern"] },
  web_search: { name: "Search web", kind: "search", fields: ["query"] },
  browser_navigate: { name: "Open page", kind: "browser", fields: ["url"] },
  browser_screenshot: {
    name: "Take screenshot",
    kind: "browser",
    fields: ["filename"],
  },
  browser_evaluate: {
    name: "Evaluate script",
    kind: "browser",
    fields: ["script", "expression"],
  },
  browser_console: { name: "Read browser console", kind: "browser" },
  browser_snapshot: { name: "Inspect page", kind: "browser" },
  browser_click: {
    name: "Click element",
    kind: "browser",
    fields: ["element", "selector", "ref"],
  },
  browser_fill: {
    name: "Fill field",
    kind: "browser",
    fields: ["element", "selector", "ref"],
  },
  document_vulnerability: {
    name: "Document finding",
    kind: "finding",
    fields: ["title", "name"],
  },
  document_finding: {
    name: "Document finding",
    kind: "finding",
    fields: ["title", "name"],
  },
  run_attack_surface: {
    name: "Map attack surface",
    kind: "agent",
    fields: ["target"],
  },
  spawn_recon_agent: { name: "Run recon agents", kind: "agent" },
  spawn_coding_agent: { name: "Run coding agents", kind: "agent" },
  spawn_pentest_swarm: { name: "Run pentest swarm", kind: "agent" },
  spawn_pentest_agent: {
    name: "Run pentest agent",
    kind: "agent",
    fields: ["name", "target"],
  },
  run_pentest_workflow: {
    name: "Run pentest",
    kind: "agent",
    fields: ["target"],
  },
  delegate_to_auth_subagent: {
    name: "Authenticate",
    kind: "agent",
    fields: ["target", "reason"],
  },
  task: { name: "Run task", kind: "agent", fields: ["description"] },
  create_task: { name: "Create task", kind: "generic", fields: ["subject"] },
  update_task: { name: "Update task", kind: "generic", fields: ["taskId"] },
  summarize_conversation: { name: "Compact context", kind: "generic" },
};
const aliases: Record<string, string> = {
  Read: "read_file",
  readFileTool: "read_file",
  Write: "write_file",
  writeFileTool: "write_file",
  Edit: "update_file",
  editFileTool: "update_file",
  Grep: "grep",
  grepTool: "grep",
  Glob: "glob",
  globTool: "glob",
  listFilesTool: "list_files",
  Task: "task",
};

export function canonicalToolName(name: string): string {
  return Object.hasOwn(aliases, name) ? aliases[name] : name;
}

export function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}
export function formatToolData(value: unknown): string {
  if (value === undefined) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2) ?? String(value);
  } catch {
    return String(value);
  }
}
function normalize(
  value: unknown,
  unwrap = true,
): { value: unknown; error: boolean } {
  let error = false;
  // Bound parsing work while retaining the original text for large or partial payloads.
  for (let depth = 0; depth < 4; depth++) {
    if (
      typeof value === "string" &&
      value.length <= 1_000_000 &&
      /^[\s]*[\[{]/.test(value)
    ) {
      try {
        value = JSON.parse(value);
      } catch {
        break;
      }
    }
    const record = asRecord(value);
    if (
      !unwrap ||
      !record ||
      !Object.hasOwn(record, "value") ||
      Object.keys(record).some(
        (key) => key !== "type" && key !== "value" && key !== "providerOptions",
      ) ||
      !["json", "text", "error-json", "error-text"].includes(
        String(record.type),
      )
    )
      break;
    error ||= record.type === "error-json" || record.type === "error-text";
    value = record.value;
  }
  return { value, error };
}
function text(
  record: Record<string, unknown> | undefined,
  ...fields: string[]
) {
  for (const field of fields) {
    const value = record?.[field];
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" && Number.isFinite(value))
      return String(value);
  }
  return undefined;
}
function number(
  record: Record<string, unknown> | undefined,
  ...fields: string[]
) {
  for (const field of fields) {
    const value = record?.[field];
    if (typeof value === "number" && Number.isFinite(value)) return value;
  }
  return undefined;
}
function readable(name: string) {
  const words = name.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[_-]/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}
function plural(count: number, unit: string) {
  return `${count} ${unit}${count === 1 ? "" : "s"}`;
}
function hasError(value: unknown) {
  return (
    value !== undefined &&
    value !== null &&
    value !== false &&
    value !== "" &&
    value !== 0
  );
}

export function describeTool(message: OperatorMessage): ToolPresentation {
  const rawName = message.toolName ?? "tool";
  const tool = canonicalToolName(rawName);
  const definition: ToolDefinition = Object.hasOwn(definitions, tool)
    ? definitions[tool]
    : { name: readable(tool), kind: "generic" };
  const input = normalize(message.args, false).value;
  const normalized = normalize(message.result);
  const output = normalized.value;
  const args = asRecord(input);
  const result = asRecord(output);
  let detail = text(args, ...(definition.fields ?? []));
  if (definition.kind === "http" && detail)
    detail = `${text(args, "method")?.toUpperCase() ?? "GET"} ${detail}`;
  if ((tool === "grep" || tool === "glob") && detail) {
    const directory = text(args, "directory", "path");
    if (directory) detail += ` in ${directory}`;
  }
  const description = text(args, "toolCallDescription");
  const headline = description ?? detail ?? definition.name;
  const exitCode = number(result, "exitCode");
  const httpStatus =
    definition.kind === "http"
      ? number(result, "status", "statusCode")
      : undefined;
  const duplicate = definition.kind === "finding" && result?.duplicate === true;
  const failed =
    normalized.error ||
    (!duplicate &&
      (result?.success === false ||
        result?.isError === true ||
        hasError(result?.error) ||
        hasError(result?.errorMessage) ||
        result?.blocked === true ||
        result?.pocFailed === true ||
        result?.judgeRejected === true ||
        (definition.kind === "command" &&
          exitCode !== undefined &&
          exitCode !== 0)));
  let status: ToolStatus;
  if (
    message.status === "cancelled" ||
    message.status === "canceled" ||
    result?.cancelled === true
  )
    status = "cancelled";
  else if (message.status === "error" || message.status === "failed" || failed)
    status = "error";
  else if (message.status === "streaming" || message.status === "running")
    status = "running";
  else if (message.status === "pending") status = "pending";
  else if (
    message.status === "completed" ||
    (!message.status && output !== undefined)
  )
    status = "completed";
  else status = "unknown";

  let summary: string | undefined;
  if (status === "error")
    summary =
      text(
        result,
        "error",
        "errorMessage",
        "message",
        "judgeReasoning",
        "stderr",
      ) ??
      (normalized.error && typeof output === "string" ? output : undefined);
  if (!summary && httpStatus !== undefined)
    summary = `HTTP ${httpStatus}${text(result, "statusText") ? ` ${text(result, "statusText")}` : ""}`;
  if (
    !summary &&
    (tool === "execute_command" || tool === "document_vulnerability") &&
    result?.status === "running"
  )
    summary = "Started in background";
  if (!summary && definition.kind === "command" && exitCode !== undefined)
    summary = `Exit ${exitCode}`;
  if (!summary && tool === "read_file") {
    const content =
      typeof output === "string"
        ? output
        : typeof result?.content === "string"
          ? result.content
          : undefined;
    const count =
      number(result, "totalLines") ??
      (content === undefined
        ? undefined
        : content
          ? content.split("\n").length
          : 0);
    if (count !== undefined) summary = plural(count, "line");
  }
  const replacements = number(result, "replacements");
  if (!summary && tool === "update_file" && replacements !== undefined)
    summary = plural(replacements, "replacement");
  if (!summary && tool === "list_files") {
    const count =
      number(result, "totalFound", "count") ??
      (Array.isArray(result?.files) ? result.files.length : undefined);
    if (count !== undefined)
      summary = `${result?.totalFoundLowerBound === true ? "At least " : ""}${plural(count, "file")}${result?.truncated === true ? " (truncated)" : ""}`;
  }
  if (!summary && definition.kind === "search") {
    const count =
      number(result, "matchCount", "count") ??
      (Array.isArray(result?.results)
        ? result.results.length
        : Array.isArray(output)
          ? output.length
          : undefined);
    if (count !== undefined)
      summary =
        count === 0
          ? "No results"
          : plural(count, tool === "grep" ? "match" : "result").replace(
              "matchs",
              "matches",
            );
  }
  if (!summary && definition.kind === "finding") {
    const finding = asRecord(result?.finding);
    summary = duplicate ? "Already documented" : text(finding, "title");
    const severity = text(finding, "severity");
    if (summary && severity) summary = `${severity.toUpperCase()} · ${summary}`;
  }
  if (!summary && definition.kind === "browser")
    summary = text(result, "title", "url", "screenshot");
  if (!summary) summary = text(result, "message", "summary");
  if (!summary && status === "error") summary = "Tool failed";
  return {
    name: definition.name,
    kind: definition.kind,
    headline,
    description:
      description && detail && detail !== description ? detail : undefined,
    status,
    summary,
    input,
    output,
  };
}

export function toolMessageKey(
  message: OperatorMessage,
  index: number,
): string {
  return message.toolCallId
    ? `tool:${message.toolCallId}`
    : `${message.role}:${message.createdAt}:${index}`;
}

export function groupTranscript(messages: OperatorMessage[]): TranscriptRow[] {
  const rows: TranscriptRow[] = [];
  messages.forEach((message, index) => {
    const key = toolMessageKey(message, index);
    if (message.role !== "tool") {
      // Empty streamed messages still separate rails; later text must not regroup tools.
      rows.push({ kind: "message", key, message });
      return;
    }
    const previous = rows.at(-1);
    if (previous?.kind === "tools") previous.items.push(message);
    else rows.push({ kind: "tools", key, items: [message] });
  });
  return rows;
}

export type ToolFamily = "repository" | "command" | "request" | "browser";
export interface ToolSegment {
  key: string;
  family: ToolFamily | null;
  items: OperatorMessage[];
}

function toolFamily(name: string): ToolFamily | null {
  const canonical = canonicalToolName(name);
  if (["read_file", "list_files", "grep", "glob"].includes(canonical))
    return "repository";
  if (canonical === "execute_command") return "command";
  if (canonical === "http_request") return "request";
  if (canonical.startsWith("browser_") && !canonical.endsWith("screenshot"))
    return "browser";
  return null;
}

export function segmentTools(items: OperatorMessage[]): ToolSegment[] {
  const segments: ToolSegment[] = [];
  items.forEach((message, index) => {
    const family = toolFamily(message.toolName ?? "tool");
    const previous = segments.at(-1);
    if (
      family &&
      previous &&
      (previous.family === family ||
        (previous.items.length === 1 &&
          toolFamily(previous.items[0].toolName ?? "tool") === family))
    ) {
      previous.family = family;
      previous.items.push(message);
    } else {
      segments.push({
        key: toolMessageKey(message, index),
        family: null,
        items: [message],
      });
    }
  });
  return segments;
}

export function toolGroupLabel(family: ToolFamily, count: number): string {
  switch (family) {
    case "repository":
      return "Worked in the repository";
    case "command":
      return `Ran ${plural(count, "command")}`;
    case "request":
      return `Made ${plural(count, "request")}`;
    case "browser":
      return `Took ${plural(count, "browser action")}`;
  }
}

export function toolGroupDetail(items: OperatorMessage[]): string {
  const runs: { name: string; count: number }[] = [];
  for (const message of items) {
    const name = canonicalToolName(message.toolName ?? "tool");
    const previous = runs.at(-1);
    if (previous?.name === name) previous.count++;
    else runs.push({ name, count: 1 });
  }
  return runs
    .map(({ name, count }) => {
      switch (name) {
        case "read_file":
          return `read ${plural(count, "file")}`;
        case "list_files":
          return `listed ${count} ${count === 1 ? "directory" : "directories"}`;
        case "grep":
          return `searched ${plural(count, "pattern")}`;
        case "glob":
          return `searched ${plural(count, "file pattern")}`;
        default:
          return "";
      }
    })
    .filter(Boolean)
    .join(", ");
}
