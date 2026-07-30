/**
 * Desktop environment support: install + launch a build artifact from a
 * `pensar-build.json` manifest inside a Windows / macOS / Linux sandbox.
 *
 * Public API for the module — import from here, not the internals.
 */

// Computer-use (desktop GUI automation) command builders. The install/launch
// builders (shellRun / launchCommand / readinessProbe) stay module-internal —
// only the runner uses them.
export {
  keyPressCommand,
  mouseClickCommand,
  mouseDoubleClickCommand,
  mouseDragCommand,
  mouseMoveCommand,
  screenInfoCommand,
  screenshotCommand,
  scrollCommand,
  typeTextCommand,
} from "./commands";
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
