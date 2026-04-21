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
  /**
   * Optional: upload a text/binary payload to a path inside the sandbox.
   *
   * `ConsoleSandbox` (from `@console/sandbox`) implements this via the
   * Daytona SDK's native `sandbox.fs.uploadFile`, which is ~10× faster
   * than base64-over-execute for anything larger than a few KB and
   * avoids shell-escape hazards. Callers that may receive a minimal
   * test double (execute-only) should feature-test with `typeof
   * sandbox.uploadFile === "function"` and fall back to a base64
   * heredoc via `execute` when it's absent.
   */
  uploadFile?(content: string | Buffer, remotePath: string): Promise<void>;
}
