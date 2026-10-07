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

/**
 * Classic findings persist host session artifacts even when execution is
 * remote. The default instance allows unlimited retained text for artifact
 * writers; pass `maxTextFileBytes` for a fresh, session-scoped instance whose
 * reads are byte-capped (not memoised alongside the unlimited default).
 */
export function resolveArtifactFs(
  ctx: ToolContext,
  options: { maxTextFileBytes?: number } = {},
): ToolBackends["fs"] {
  if (ctx.backends) return ctx.backends.fs;
  if (options.maxTextFileBytes !== undefined) {
    return LocalBackends(
      {
        ...ctx,
        sandbox: undefined,
        agentCwd: ctx.session.rootPath,
        fileWorkspaceRoot: ctx.session.rootPath,
      },
      undefined,
      { maxTextFileBytes: options.maxTextFileBytes },
    ).fs;
  }
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

function posixQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

// Safe literal option arguments (flags) pass through unquoted so journalled
// command bytes stay readable; anything else is single-quoted.
function posixFlagArg(value: string): string {
  return /^[-A-Za-z0-9_@+=:,./]+$/.test(value) ? value : posixQuote(value);
}

/**
 * Transport for one program invocation: runner, option args, and a final
 * target path. The final argument is always single-quoted (remote transports
 * journal these exact command bytes); earlier args pass through unquoted
 * when they are safe literals.
 */
export function resolveProgramRunner(ctx: ToolContext) {
  const command =
    ctx.backends || ctx.sandbox ? resolveBackends(ctx).command : undefined;
  // Injected command backends see only RunOpts, so the agent's configured
  // environment is merged here with per-call envVars winning. The local and
  // classic sandbox transports already merge it themselves. Options pass
  // through untouched when there is nothing to merge.
  const withConfiguredEnv = (options: RunOpts | undefined) =>
    ctx.environmentVariables || options?.envVars
      ? {
          ...options,
          envVars: { ...ctx.environmentVariables, ...options?.envVars },
        }
      : options;
  return (runner: string, args: string[], options?: RunOpts) => {
    if (command?.platform === "windows") {
      const invocation = windowsProgramInvocation(runner, args);
      return command.run(invocation.command, {
        ...options,
        envVars: {
          ...ctx.environmentVariables,
          ...options?.envVars,
          ...invocation.envVars,
        },
      });
    }
    const commandText = [
      runner,
      ...args.slice(0, -1).map(posixFlagArg),
      posixQuote(args[args.length - 1] ?? ""),
    ].join(" ");
    return command
      ? command.run(commandText, withConfiguredEnv(options))
      : runLocalProgram(ctx, commandText, runner, args, options);
  };
}

/** Native scripts use argv; remote scripts retain their journalled command bytes. */
export function resolveScriptRunner(ctx: ToolContext) {
  const runProgram = resolveProgramRunner(ctx);
  return (runner: string, scriptPath: string, options?: RunOpts) =>
    runProgram(runner, [scriptPath], options);
}
