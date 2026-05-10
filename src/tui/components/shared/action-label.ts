import type { PendingApproval } from "../../../core/operator";
import { getToolSummary } from "./tool-registry";

/** Derive a human-readable label for a tool call. Prefers `args.toolCallDescription`, falls back to `getToolSummary`. */
export function deriveActionLabel(
  toolName: string,
  args: Record<string, unknown> | undefined,
): string {
  const description = args?.toolCallDescription;
  if (typeof description === "string" && description.trim().length > 0) {
    return description.trim();
  }
  return getToolSummary(toolName, args ?? {});
}

export function deriveApprovedActionLabel(approval: PendingApproval): string {
  return deriveActionLabel(approval.toolName, approval.args);
}
