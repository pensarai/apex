import type { ToolSet } from "ai";

/**
 * Reduce the executable tool map to the allowlist.
 *
 * The AI SDK's `activeTools` only controls which tools the model is *shown*;
 * every entry left in the tool map stays callable, so a model that names a
 * tool it was never shown (e.g. a builtin `execute_command`) still runs it.
 * Callers that need a hard boundary — e.g. workspace chat, which exposes a
 * curated subset of the pentest registry — pass their allowlist here so
 * unlisted names raise NoSuchTool instead of silently executing.
 */
export function restrictToolsToActive(
  tools: ToolSet,
  activeToolNames: readonly string[],
): ToolSet {
  const allowed = new Set(activeToolNames);
  return Object.fromEntries(
    Object.entries(tools).filter(([name]) => allowed.has(name)),
  ) as ToolSet;
}
