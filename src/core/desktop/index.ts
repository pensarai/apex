/**
 * Desktop environment support: install + launch a build artifact from a
 * `pensar-build.json` manifest inside a Windows / macOS / Linux sandbox, plus
 * per-OS command builders for driving the desktop.
 *
 * Public API for the module — import from here, not the internals.
 */

export {
  launchCommand,
  readinessProbe,
  screenshotCommand,
  shellRun,
} from "./commands";
export {
  type RunBuildOptions,
  type RunBuildResult,
  runBuildManifest,
  teardownBuild,
} from "./runner";
export type {
  BuildManifest,
  BuildManifestLaunchEnv,
  DesktopExec,
  DesktopExecResult,
  DesktopOs,
  ReadinessCheck,
} from "./types";
export { SUPPORTED_MANIFEST_VERSION } from "./types";
