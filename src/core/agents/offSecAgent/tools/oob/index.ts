/**
 * OOB interaction detection tools.
 *
 * Provides three tools that let agents detect blind vulnerabilities
 * using interactsh callback URLs (DNS, HTTP, SMTP, LDAP interactions).
 */

export { oobStartListener } from "./startOobListener";
export { oobPollInteractions } from "./pollOobInteractions";
export { oobStopListener } from "./stopOobListener";

import type { ToolContext } from "../types";
import { oobStartListener } from "./startOobListener";
import { oobPollInteractions } from "./pollOobInteractions";
import { oobStopListener } from "./stopOobListener";

/**
 * Create the full OOB interaction detection toolset.
 * All three tools share the same ToolContext and its `oobClientHolder`.
 */
export function createOobToolset(ctx: ToolContext) {
  return {
    oob_start_listener: oobStartListener(ctx),
    oob_poll_interactions: oobPollInteractions(ctx),
    oob_stop_listener: oobStopListener(ctx),
  } as const;
}

/** All OOB tool names as a typed array. */
export const OOB_TOOL_NAMES = [
  "oob_start_listener",
  "oob_poll_interactions",
  "oob_stop_listener",
] as const;

export type OobToolName = (typeof OOB_TOOL_NAMES)[number];
