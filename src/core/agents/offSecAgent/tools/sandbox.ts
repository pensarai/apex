/**
 * Minimal sandbox interface consumed by apex tools.
 *
 * `ConsoleSandbox` from `@console/sandbox` structurally satisfies this
 * interface, so callers can pass it directly:
 *
 * @example
 * ```ts
 * const sandbox = await createSandbox({ image, type: 'linux' });
 * // sandbox satisfies UnifiedSandbox
 * ```
 */

export type SandboxType = "linux" | "windows";

export interface SandboxExecuteOptions {
  cwd?: string;
  envVars?: Record<string, string>;
  timeout?: number;
  retries?: number;
}

export interface SandboxExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  success: boolean;
}

export interface UnifiedSandbox {
  type: SandboxType;
  execute(
    command: string,
    opts?: SandboxExecuteOptions,
  ): Promise<SandboxExecutionResult>;
}
