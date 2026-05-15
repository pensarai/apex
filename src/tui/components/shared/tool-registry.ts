/**
 * Tool Summary Registry
 *
 * Centralized registry for generating human-readable tool summaries.
 * Replaces 5 duplicate getToolSummary() implementations.
 *
 * Inspired by OpenCode's extensible tool display pattern.
 */

type ToolSummaryFn = (args: Record<string, unknown>) => string;

/**
 * Registry of tool name to summary function mappings.
 */
const TOOL_SUMMARY_MAP: Record<string, ToolSummaryFn> = {
  // HTTP/Network tools
  http_request: (args) => {
    const method = ((args.method as string) || "GET").toUpperCase();
    const url = (args.url as string) || "";
    return `${method} ${url}`;
  },
  crawl: (args) => `crawl ${args.url || args.target || ""}`,

  // Shell/Command tools
  execute_command: (args) => {
    const cmd = String(args.command || "").split("\n")[0];
    return cmd.length > 80 ? `$ ${cmd.slice(0, 80)}…` : `$ ${cmd}`;
  },

  // File system tools
  read_file: (args) => `read ${args.path || ""}`,
  Read: (args) => `read ${args.path || args.file_path || ""}`,
  write_file: (args) => `write ${args.path || ""}`,
  Write: (args) => `write ${args.path || args.file_path || ""}`,
  create_file: (args) => `create ${args.path || ""}`,
  update_file: (args) => `update ${args.path || ""}`,
  document_vulnerability: (args) => {
    const title = args.title || args.name || "";
    const pocName = args.pocName || "";
    return pocName
      ? `finding: ${title} (poc: ${pocName})`
      : `finding: ${title}`;
  },
  Edit: (args) => `edit ${args.file_path || args.path || ""}`,
  Grep: (args) => `grep ${args.pattern || ""}`,
  grep: (args) => `grep ${args.pattern || ""}`,
  Glob: (args) => `glob ${args.pattern || ""}`,

  // Web search
  web_search: (args) => `search "${args.query || ""}"`,

  // Browser tools
  browser_navigate: (args) => `browser ${args.url || ""}`,
  browser_console: () => "browser_console",
  browser_evaluate: (args) => {
    const script = (args.script as string) || (args.expression as string) || "";
    return `eval ${script.slice(0, 40)}${script.length > 40 ? "..." : ""}`;
  },
  browser_screenshot: () => "screenshot",

  // Security tools
  nuclei_scan: (args) =>
    `nuclei ${args.templates || "all"} -> ${args.target || ""}`,
  document_finding: (args) => `finding: ${args.title || args.name || ""}`,
  list_prompt_injections: (args) =>
    args.category
      ? `prompt injections: ${args.category}`
      : "prompt injections",
  smart_enumerate: (args) => `smart_enumerate ${args.target || args.url || ""}`,
  get_attack_surface: (args) =>
    `get_attack_surface ${args.target || args.url || ""}`,

  // Task/Agent tools
  Task: (args) => (args.description as string) || "Task",
  task: (args) => (args.description as string) || "task",

  // Task decomposition tools — labels are minimal, icons on results only
  create_task: (args) => {
    const subject = (args.subject as string) || "task";
    return subject;
  },
  update_task: (args) => {
    const id = args.taskId ?? "?";
    const status = (args.status as string) || "";
    return `task #${id} → ${status}`;
  },
  list_tasks: () => "tasks",

  // Subagent-spawning tools
  run_attack_surface: (args) => {
    const mode = args.cwd ? "whitebox" : "blackbox";
    return `recon (${mode}) ${args.target || ""}`;
  },
  spawn_coding_agent: (args) => {
    const tasks = args.tasks as unknown[];
    return `coding agents ×${tasks?.length ?? "?"}`;
  },
  spawn_pentest_swarm: (args) => {
    const targets = args.targets as unknown[];
    return `pentest swarm ×${targets?.length ?? "?"}`;
  },
  spawn_pentest_agent: (args) => {
    const name = (args.name as string) ?? "pentest worker";
    return `pentest worker — ${name}`;
  },
  run_pentest_workflow: (args) => {
    const mode = args.cwd ? "whitebox" : "blackbox";
    return `pentest workflow (${mode}) ${args.target || ""}`;
  },
  profile_codebase: (args) =>
    `profile codebase${args.path ? ` ${args.path}` : ""}`,
  query_whitebox_catalog: (args) =>
    `whitebox catalog ${args.query || args.kind || ""}`,
  run_code_query: (args) => {
    const engine = (args.engine as string) || "rg";
    const queries = args.queries as unknown[];
    return `${engine} query ×${queries?.length ?? "?"}`;
  },
  run_whitebox_scan: (args) => `whitebox scan ${args.kind || ""}`,
  create_whitebox_candidate: (args) =>
    `candidate: ${args.title || args.vulnerabilityClass || ""}`,
  update_whitebox_candidate: (args) => `candidate ${args.id || ""}`,
  list_whitebox_candidates: (args) =>
    `candidates ${args.state ? `(${args.state})` : ""}`,
  start_whitebox_job: (args) => `whitebox job ${args.name || ""}`,
  poll_whitebox_job: (args) => `poll job ${args.jobId || ""}`,
  stop_whitebox_job: (args) => `stop job ${args.jobId || ""}`,
  read_whitebox_artifact: (args) =>
    args.path ? `artifact ${args.path}` : `job log ${args.jobId || ""}`,
  delegate_to_auth_subagent: (args) =>
    `auth ${args.target || ""} — ${args.reason || ""}`,

  // Memory tools
  add_memory: (args) => `remember "${args.title || ""}"`,
  list_memories: (args) => {
    const parts: string[] = ["list memories"];
    if (args.category) parts.push(`[${args.category}]`);
    if (args.tag) parts.push(`tag:${args.tag}`);
    return parts.join(" ");
  },
  get_memory: (args) => `recall ${args.category || ""}/${args.id || ""}`,

  // Utility tools
  scratchpad: () => "note",
};

/**
 * Get a human-readable summary for a tool call.
 *
 * @param toolName - Name of the tool
 * @param args - Tool arguments
 * @returns Human-readable summary string
 */
export function getToolSummary(
  toolName: string,
  args: Record<string, unknown>,
): string {
  // Check registry first
  const summaryFn = TOOL_SUMMARY_MAP[toolName];
  let summary: string;
  if (summaryFn) {
    summary = summaryFn(args);
  } else {
    // Fallback: use first non-description arg value
    const firstArg = Object.entries(args)
      .filter(([k]) => k !== "toolCallDescription")
      .map(([, v]) => (typeof v === "string" ? v : JSON.stringify(v)))
      .find((v) => v && v.length > 0);

    summary = firstArg
      ? `${toolName} ${String(firstArg).slice(0, 50)}`
      : toolName;
  }
  return summary;
}

/**
 * Get the label shown in the live tool header.
 *
 * Pending shell commands should prefer the model-provided human description
 * over partial command text while the tool call is still streaming/executing.
 */
export function getToolDisplayLabel(
  toolName: string,
  args: Record<string, unknown>,
  options: { preferDescription?: boolean } = {},
): string {
  if (options.preferDescription && toolName === "execute_command") {
    const description = args.toolCallDescription;
    if (typeof description === "string" && description.trim().length > 0) {
      return description.trim();
    }
  }

  return getToolSummary(toolName, args);
}

/**
 * Register a custom tool summary function.
 * Allows extensions to add their own tool displays.
 *
 * @param name - Tool name
 * @param fn - Summary function
 */
function registerToolSummary(name: string, fn: ToolSummaryFn): void {
  TOOL_SUMMARY_MAP[name] = fn;
}

/**
 * Check if a tool has a registered summary function.
 */
function hasToolSummary(name: string): boolean {
  return name in TOOL_SUMMARY_MAP;
}

/**
 * Get a compact args preview for display alongside tool calls.
 * Shows key parameter values in a truncated format.
 *
 * @param toolName - Name of the tool
 * @param args - Tool arguments
 * @param maxLength - Maximum length of preview (default 60)
 * @returns Compact args preview string
 */
export function getArgsPreview(
  toolName: string,
  args: Record<string, unknown>,
  maxLength: number = 60,
): string {
  // Filter out description fields
  const filteredArgs = Object.entries(args).filter(
    ([k]) => !k.toLowerCase().includes("description"),
  );

  if (filteredArgs.length === 0) return "";

  // For single-arg tools, just show the value
  if (filteredArgs.length === 1) {
    const [, value] = filteredArgs[0];
    const str = typeof value === "string" ? value : JSON.stringify(value);
    const truncated =
      str.length > maxLength ? str.slice(0, maxLength) + "…" : str;
    return truncated;
  }

  // For multi-arg tools, show key:value pairs
  const parts = filteredArgs.map(([key, value]) => {
    const shortKey = key
      .replace(/([A-Z])/g, "_$1")
      .toLowerCase()
      .replace(/^_/, "");
    let shortValue: string;
    if (typeof value === "string") {
      shortValue = value.length > 20 ? value.slice(0, 20) + "…" : value;
    } else if (typeof value === "boolean") {
      shortValue = value ? "✓" : "✗";
    } else if (typeof value === "number") {
      shortValue = String(value);
    } else if (Array.isArray(value)) {
      shortValue = `[${value.length}]`;
    } else {
      shortValue = "{…}";
    }
    return `${shortKey}:${shortValue}`;
  });

  const preview = parts.join(" ");
  const truncated =
    preview.length > maxLength ? preview.slice(0, maxLength) + "…" : preview;
  return truncated;
}
