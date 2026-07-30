/**
 * Desktop environment support: install + launch a build artifact from a
 * `pensar-build.json` manifest inside a Windows / macOS / Linux sandbox.
 *
 * Public API for the module — import from here, not the internals.
 */

export {
  type RunBuildOptions,
  type RunBuildResult,
  runBuildManifest,
} from "./runner";
export type {
  BuildManifest,
  DesktopExec,
  DesktopExecResult,
  DesktopOs,
  ReadinessCheck,
} from "./types";
