/**
 * Desktop build-manifest runner: install → launch → wait-for-ready.
 *
 * Consumes a `pensar-build.json` produced by the Console and executes it inside
 * the desktop environment via an injected `DesktopExec` (a Daytona sandbox's
 * `execute`, or a local shell when the agent runs inside the sandbox). Sequences
 * are deterministic; the model is only involved once the app is up.
 */
import { launchCommand, readinessProbe, shellRun } from "./commands";
import {
  type BuildManifest,
  type DesktopExec,
  type DesktopOs,
  SUPPORTED_MANIFEST_VERSION,
} from "./types";

export interface RunBuildOptions {
  exec: DesktopExec;
  os: DesktopOs;
  manifest: BuildManifest;
  // Injected for testability; defaults to real wall-clock sleep.
  sleep?: (ms: number) => Promise<void>;
  // Poll cadence for readiness probes.
  pollIntervalMs?: number;
  onLog?: (line: string) => void;
}

export interface RunBuildResult {
  installed: boolean;
  launched: boolean;
  ready: boolean;
  readinessKind: string | null;
}

const DEFAULT_READINESS_TIMEOUT_S = 60;
const DEFAULT_POLL_INTERVAL_MS = 2000;

const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function waitForReadiness(
  opts: Required<Pick<RunBuildOptions, "exec" | "os" | "sleep">> & {
    manifest: BuildManifest;
    pollIntervalMs: number;
    onLog?: (line: string) => void;
  },
): Promise<boolean> {
  const check = opts.manifest.readinessCheck;
  if (!check) return true;

  if (check.kind === "sleep") {
    await opts.sleep(check.seconds * 1000);
    return true;
  }

  const probe = readinessProbe(opts.os, check);
  if (!probe) return true;

  const timeoutMs =
    (("timeoutSeconds" in check && check.timeoutSeconds) ||
      DEFAULT_READINESS_TIMEOUT_S) * 1000;
  const deadline = Date.now() + timeoutMs;

  // First attempt immediately, then poll until the deadline.
  for (;;) {
    const res = await opts.exec(probe);
    if (res.success) return true;
    if (Date.now() >= deadline) {
      opts.onLog?.(
        `readiness (${check.kind}) not satisfied within ${timeoutMs / 1000}s`,
      );
      return false;
    }
    await opts.sleep(opts.pollIntervalMs);
  }
}

export async function runBuildManifest(
  opts: RunBuildOptions,
): Promise<RunBuildResult> {
  const { exec, os, manifest } = opts;
  const sleep = opts.sleep ?? realSleep;
  const pollIntervalMs = opts.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;

  if (manifest.manifestVersion !== SUPPORTED_MANIFEST_VERSION) {
    throw new Error(
      `Unsupported build manifest version ${manifest.manifestVersion} (this runner supports ${SUPPORTED_MANIFEST_VERSION}).`,
    );
  }

  // 1. Install.
  opts.onLog?.(`installing (${manifest.install.mode})`);
  const install = await exec(shellRun(os, manifest.install.script));
  if (!install.success) {
    throw new Error(
      `Install step failed (exit ${install.exitCode}): ${install.stderr || install.stdout}`,
    );
  }

  // 2. Launch (skip when no executable — e.g. a headless service build).
  let launched = false;
  if (manifest.launch.executablePath) {
    opts.onLog?.(`launching ${manifest.launch.executablePath}`);
    const launch = await exec(launchCommand(os, manifest.launch));
    if (!launch.success) {
      throw new Error(
        `Launch step failed (exit ${launch.exitCode}): ${launch.stderr || launch.stdout}`,
      );
    }
    launched = true;
  }

  // 3. Wait for readiness.
  const ready = await waitForReadiness({
    exec,
    os,
    sleep,
    manifest,
    pollIntervalMs,
    onLog: opts.onLog,
  });

  return {
    installed: true,
    launched,
    ready,
    readinessKind: manifest.readinessCheck?.kind ?? null,
  };
}

export async function teardownBuild(opts: {
  exec: DesktopExec;
  os: DesktopOs;
  manifest: BuildManifest;
}): Promise<void> {
  const { exec, os, manifest } = opts;
  if (!manifest.teardownScript) return;
  // Best-effort — the sandbox is destroyed regardless.
  await exec(shellRun(os, manifest.teardownScript));
}
