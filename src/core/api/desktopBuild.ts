/**
 * Run a desktop build from a `pensar-build.json` manifest.
 *
 * Executes install → launch → readiness locally (via the OS shell) — the shape
 * used when the agent runs *inside* a Windows/macOS/Linux sandbox. The heavy
 * lifting + per-OS command building lives in `core/desktop`; this is the thin
 * public entrypoint that wires a local executor and reads the manifest.
 */
import { exec as cpExec } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import {
  type BuildManifest,
  type DesktopExec,
  type DesktopOs,
  type RunBuildResult,
  runBuildManifest,
} from "../desktop";

const pexec = promisify(cpExec);

const localExec: DesktopExec = async (command, opts) => {
  try {
    const { stdout, stderr } = await pexec(command, {
      cwd: opts?.cwd,
      env: opts?.envVars ? { ...process.env, ...opts.envVars } : process.env,
      timeout: opts?.timeout ? opts.timeout * 1000 : undefined,
      maxBuffer: 32 * 1024 * 1024,
    });
    return { stdout, stderr, exitCode: 0, success: true };
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string; code?: number };
    return {
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? String(e),
      exitCode: typeof err.code === "number" ? err.code : 1,
      success: false,
    };
  }
};

const VALID_OS: DesktopOs[] = ["linux", "windows", "macos"];

function osFromManifest(platform: string): DesktopOs {
  if ((VALID_OS as string[]).includes(platform)) return platform as DesktopOs;
  throw new Error(
    `Manifest artifact.platform "${platform}" is not a runnable desktop OS (${VALID_OS.join(", ")}).`,
  );
}

export interface RunDesktopBuildInput {
  manifestPath: string;
  os?: DesktopOs;
  onLog?: (line: string) => void;
}

export async function runDesktopBuild(
  input: RunDesktopBuildInput,
): Promise<RunBuildResult> {
  const raw = await readFile(input.manifestPath, "utf8");
  const manifest = JSON.parse(raw) as BuildManifest;
  const os = input.os ?? osFromManifest(manifest.artifact.platform);
  return runBuildManifest({
    exec: localExec,
    os,
    manifest,
    onLog: input.onLog,
  });
}
