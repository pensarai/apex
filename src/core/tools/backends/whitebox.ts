import { resolveFilePath } from "../../agents/offSecAgent/tools/fileWorkspace";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import {
  resolvePathWithinCodebaseRoot,
  resolveWhiteboxCodebaseRoot,
} from "../../whitebox";
import { resolveBoundedCommandRunner } from "../../whitebox/boundedProcess";
import { createRepoProfileIO } from "../../whitebox/profileTransport";
import { resolveBackends } from "./resolve";

export async function resolveWhiteboxPath(
  ctx: ToolContext,
  requestedPath?: string,
): Promise<string> {
  const configuredRoot = ctx.session.config?.codebasePath;
  if (ctx.mode !== "default-v2") {
    const root = resolveWhiteboxCodebaseRoot({
      agentCwd: ctx.agentCwd,
      codebasePath: configuredRoot,
    });
    return resolvePathWithinCodebaseRoot(root, requestedPath ?? ".");
  }
  // A launch directory is a default location; explicit codebase and file scopes remain boundaries.
  const path = configuredRoot
    ? await resolveFilePath(
        { ...ctx, fileWorkspaceRoot: configuredRoot },
        requestedPath ?? ".",
      )
    : (requestedPath ?? ".");
  return resolveFilePath(ctx, path);
}

/** Native argv/filesystem semantics for local callers; owned sandbox or injected transport otherwise. */
export function resolveWhiteboxBackend(ctx: ToolContext) {
  const command =
    ctx.backends || ctx.sandbox ? resolveBackends(ctx).command : undefined;
  return {
    profile: createRepoProfileIO(command),
    run: resolveBoundedCommandRunner(command),
  };
}
