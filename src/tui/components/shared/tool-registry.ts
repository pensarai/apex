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
  execute_command: (args) => `$ ${args.command || ""}`,

  // File system tools
  read_file: (args) => `read ${args.path || ""}`,
  Read: (args) => `read ${args.path || args.file_path || ""}`,
  write_file: (args) => `write ${args.path || ""}`,
  Write: (args) => `write ${args.path || args.file_path || ""}`,
  Edit: (args) => `edit ${args.file_path || args.path || ""}`,
  Grep: (args) => `grep ${args.pattern || ""}`,
  Glob: (args) => `glob ${args.pattern || ""}`,

  // Browser tools
  browser_navigate: (args) => `browser ${args.url || ""}`,
  browser_console: () => "browser_console",
  browser_evaluate: (args) => {
    const script = (args.script as string) || (args.expression as string) || "";
    return `eval ${script.slice(0, 40)}${script.length > 40 ? "..." : ""}`;
  },
  browser_screenshot: () => "screenshot",

  // Security tools
  nuclei_scan: (args) => `nuclei ${args.templates || "all"} -> ${args.target || ""}`,
  document_finding: (args) => `finding: ${args.title || args.name || ""}`,
  smart_enumerate: (args) => `smart_enumerate ${args.target || args.url || ""}`,
  get_attack_surface: (args) => `get_attack_surface ${args.target || args.url || ""}`,

  // Task/Agent tools
  Task: (args) => (args.description as string) || "Task",
  task: (args) => (args.description as string) || "task",

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
  args: Record<string, unknown>
): string {
  // Check registry first
  const summaryFn = TOOL_SUMMARY_MAP[toolName];
  if (summaryFn) {
    return summaryFn(args);
  }

  // Fallback: use first non-description arg value
  const firstArg = Object.entries(args)
    .filter(([k]) => k !== "toolCallDescription")
    .map(([, v]) => (typeof v === "string" ? v : JSON.stringify(v)))
    .find((v) => v && v.length > 0);

  return firstArg ? `${toolName} ${String(firstArg).slice(0, 50)}` : toolName;
}

/**
 * Register a custom tool summary function.
 * Allows extensions to add their own tool displays.
 *
 * @param name - Tool name
 * @param fn - Summary function
 */
export function registerToolSummary(name: string, fn: ToolSummaryFn): void {
  TOOL_SUMMARY_MAP[name] = fn;
}

/**
 * Check if a tool has a registered summary function.
 */
export function hasToolSummary(name: string): boolean {
  return name in TOOL_SUMMARY_MAP;
}
