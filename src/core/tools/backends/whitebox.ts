import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import { resolveBoundedCommandRunner } from "../../whitebox/boundedProcess";
import { createRepoProfileIO } from "../../whitebox/profileTransport";
import { resolveBackends } from "./resolve";

/** Native argv/filesystem semantics for local callers; owned sandbox or injected transport otherwise. */
export function resolveWhiteboxBackend(ctx: ToolContext) {
  const command =
    ctx.backends || ctx.sandbox ? resolveBackends(ctx).command : undefined;
  return {
    profile: createRepoProfileIO(command),
    run: resolveBoundedCommandRunner(command),
  };
}
