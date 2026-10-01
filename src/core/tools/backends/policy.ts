/**
 * Tool policy hook (design Appendix M): deterministic code at the exec
 * boundary, consulted before every backend call. It composes today's
 * engagement-scope checks (`assertCommandInScope` / `assertUrlInScope`) and the
 * destructive-action block (`assertCommandActionAllowed` /
 * `assertHttpActionAllowed`) — the same logic, called, not duplicated. Hosts
 * inject a policy; scope is never model discretion.
 */

import {
  assertCommandActionAllowed,
  assertHttpActionAllowed,
  DestructiveActionError,
} from "../../agents/offSecAgent/tools/destructiveGuard";
import {
  assertCommandInScope,
  assertUrlInScope,
  ScopeViolationError,
} from "../../agents/offSecAgent/tools/scopeGuard";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";

export type BackendName = "fs" | "command" | "http" | "browser" | "inbox";

export type PolicyDecision = { allow: true } | { allow: false; reason: string };

export interface ToolPolicyCall {
  backend: BackendName;
  op: string;
  args: unknown;
  ctx: ToolContext;
}

export interface ToolPolicy {
  beforeCall(call: ToolPolicyCall): PolicyDecision | Promise<PolicyDecision>;
}

/** Raised by a backend when {@link ToolPolicy.beforeCall} denies a call. */
export class ToolPolicyDeniedError extends Error {
  constructor(
    public readonly backend: BackendName,
    public readonly op: string,
    public readonly reason: string,
  ) {
    super(reason);
    this.name = "ToolPolicyDeniedError";
  }
}

interface CommandPolicyArgs {
  command: string;
}

interface HttpPolicyArgs {
  method: string;
  url: string;
  body?: string;
  headers?: Record<string, string>;
  /** `get_page`'s readability fetch: never scope- or destructive-checked (design §5.4, Appendix L). */
  extract?: "readability";
}

const ALLOW: PolicyDecision = { allow: true };

/**
 * The default policy: engagement scope + destructive-action block, exactly as
 * `execute_command` / `http_request` enforce them today. Both guards are
 * no-ops when nothing is configured (no target → no scope; destructive testing
 * authorized → no block), so unscoped local runs are unaffected.
 */
export const defaultPolicy: ToolPolicy = {
  beforeCall(call: ToolPolicyCall): PolicyDecision {
    const { ctx } = call;

    if (call.backend === "command" && call.op === "run") {
      const { command } = call.args as CommandPolicyArgs;
      try {
        assertCommandInScope(command, ctx);
        assertCommandActionAllowed(command, ctx);
      } catch (e) {
        if (
          e instanceof ScopeViolationError ||
          e instanceof DestructiveActionError
        ) {
          return { allow: false, reason: e.message };
        }
        throw e;
      }
      return ALLOW;
    }

    if (call.backend === "http" && call.op === "request") {
      const { method, url, body, headers, extract } =
        call.args as HttpPolicyArgs;
      if (extract === "readability") return ALLOW;
      try {
        assertUrlInScope(url, ctx);
        assertHttpActionAllowed({ method, url, body, headers }, ctx);
      } catch (e) {
        if (
          e instanceof ScopeViolationError ||
          e instanceof DestructiveActionError
        ) {
          return { allow: false, reason: e.message };
        }
        throw e;
      }
      return ALLOW;
    }

    return ALLOW;
  },
};
