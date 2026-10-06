import { appendLocalWorkspaceFile } from "../../agents/offSecAgent/tools/fileWorkspace";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import { LocalBackends, runLocalProgram } from "./local";
import type { RunOpts, ToolBackends, WriteResult } from "./types";
import { windowsProgramInvocation } from "./windowsProgram";

export const SANDBOX_ARTIFACTS_ROOT = "/workspace/repo/.pensar";

const localByContext = new WeakMap<ToolContext, ToolBackends>();

/** The backends a tool should execute against: injected, else local (memoised per context). */
export function resolveBackends(ctx: ToolContext): ToolBackends {
  if (ctx.backends) return ctx.backends;
  let local = localByContext.get(ctx);
  if (!local) {
    local = LocalBackends(ctx);
    localByContext.set(ctx, local);
  }
  return local;
}

const artifactsByContext = new WeakMap<ToolContext, ToolBackends["fs"]>();

/** Classic findings persist host session artifacts even when execution is remote. */
export function resolveArtifactFs(ctx: ToolContext): ToolBackends["fs"] {
  if (ctx.backends) return ctx.backends.fs;
  let fs = artifactsByContext.get(ctx);
  if (!fs) {
    fs = LocalBackends(
      {
        ...ctx,
        sandbox: undefined,
        agentCwd: ctx.session.rootPath,
        fileWorkspaceRoot: ctx.session.rootPath,
      },
      undefined,
      { maxTextFileBytes: Infinity },
    ).fs;
    artifactsByContext.set(ctx, fs);
  }
  return fs;
}

/** Keep the injected read/write journal unchanged; classic artifacts use native append. */
export async function appendArtifactSummary(
  ctx: ToolContext,
  path: string,
  header: string,
  entry: string,
): Promise<WriteResult> {
  if (ctx.backends) {
    const fs = resolveArtifactFs(ctx);
    const existing = await fs.readRaw(path);
    return fs.write(
      path,
      (existing.success ? existing.content : header) + entry,
      { mode: "overwrite" },
    );
  }
  await appendLocalWorkspaceFile(
    {
      ...ctx,
      sandbox: undefined,
      agentCwd: ctx.session.rootPath,
      fileWorkspaceRoot: ctx.session.rootPath,
    },
    path,
    header,
    entry,
  );
  return { success: true, error: "", path };
}

/** Native scripts use argv; remote scripts retain their journalled command bytes. */
export function resolveScriptRunner(ctx: ToolContext) {
  const command =
    ctx.backends || ctx.sandbox ? resolveBackends(ctx).command : undefined;
  return (runner: string, scriptPath: string, options?: RunOpts) => {
    if (command?.platform === "windows") {
      const invocation = windowsProgramInvocation(runner, [scriptPath]);
      return command.run(invocation.command, {
        ...options,
        envVars: { ...options?.envVars, ...invocation.envVars },
      });
    }
    const quotedPath = `'${scriptPath.replace(/'/g, `'\\''`)}'`;
    const commandText = `${runner} ${quotedPath}`;
    return command
      ? command.run(commandText, options)
      : runLocalProgram(ctx, commandText, runner, [scriptPath], options);
  };
}
