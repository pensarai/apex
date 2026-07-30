/**
 * Desktop-environment execution types.
 *
 * Mirrors the `pensar-build.json` contract produced by the Console
 * (`packages/core/applicationBuilds/recipe.ts` `buildBuildManifest`) so the
 * runner can install + launch a build artifact deterministically inside a
 * Windows / macOS / Linux sandbox. Keep field names in lockstep with that
 * producer.
 */

export type DesktopOs = "linux" | "windows" | "macos";

// Result of one command executed in the desktop environment. Matches the shape
// of `UnifiedSandbox.execute` so a sandbox can be passed directly as the exec.
export interface DesktopExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  success: boolean;
}

// Abstract command executor. In a Console Daytona sandbox the agent runs
// locally (exec = local shell); a host-drives-remote flow passes a
// `UnifiedSandbox.execute`. Injecting it keeps the runner testable.
export type DesktopExec = (
  command: string,
  opts?: { cwd?: string; envVars?: Record<string, string>; timeout?: number },
) => Promise<DesktopExecResult>;

export type ReadinessCheck =
  | { kind: "sleep"; seconds: number }
  | { kind: "process"; process: string; timeoutSeconds?: number }
  | { kind: "port"; port: number; timeoutSeconds?: number }
  | { kind: "window-title"; titleContains: string; timeoutSeconds?: number }
  | {
      kind: "log-line";
      path: string;
      contains: string;
      timeoutSeconds?: number;
    };

interface BuildManifestLaunchEnv {
  name: string;
  secretRef?: string;
  value?: string;
}

export interface BuildManifest {
  manifestVersion: number;
  artifact: {
    id: string;
    filename: string;
    path: string;
    format: string;
    platform: string;
    architecture: string;
    sha256: string | null;
  };
  install: {
    mode: string;
    script: string;
  };
  launch: {
    executablePath: string | null;
    args: string[];
    workingDirectory: string | null;
    environment: BuildManifestLaunchEnv[];
  };
  readinessCheck: ReadinessCheck | null;
  teardownScript: string | null;
}

export const SUPPORTED_MANIFEST_VERSION = 1;
