import { join } from "node:path";
import type { ToolContext } from "./types";

/**
 * Directory for an agent's spilled log artifacts — large HTTP response bodies
 * (`http-responses/`) and command output (`cmd-output/`).
 *
 * Scoped under the owning subagent's directory (`subagents/{subagentId}/logs`)
 * so a host that orchestrates many subagents inside ONE shared session (e.g.
 * Pensar Console runs every endpoint of a scan as a subagent under one session
 * dir) can reclaim a finished subagent's spill by removing `subagents/{id}/` —
 * the same place its `messages.json` / `{id}.trace.jsonl` already live. Without
 * this, these dumps accumulate at the shared session root for the whole scan
 * and are only freed at teardown, which can exhaust the sandbox disk (ENOSPC).
 *
 * The root/operator agent (no `subagentId`) keeps the shared session `logs/`
 * dir, so single-session runs are unchanged.
 */
export function agentLogsDir(ctx: ToolContext): string {
  return ctx.subagentId
    ? join(ctx.session.rootPath, "subagents", ctx.subagentId, "logs")
    : ctx.session.logsPath;
}
