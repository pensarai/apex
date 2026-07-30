/**
 * Computer-use tools — desktop GUI automation for driving an installed +
 * launched build artifact under test.
 *
 * Backends (resolved from `process.platform`):
 *   Linux   → xdotool + scrot / ImageMagick
 *   macOS   → cliclick + screencapture
 *   Windows → PowerShell + .NET (System.Windows.Forms / user32.dll)
 *
 * Every tool runs its per-OS command LOCALLY (the agent runs on the sandbox
 * VM) via the local executor in `./runtime`. Command STRINGS live in
 * `core/desktop/commands` so the OS dialects stay pure + unit-tested.
 *
 * Mirrors `createBrowserToolset` / `BROWSER_TOOL_NAMES`.
 */
import type { ToolContext } from "../types";
import { computerKeyPress } from "./keyPress";
import { computerMouseClick } from "./mouseClick";
import { computerMouseDoubleClick } from "./mouseDoubleClick";
import { computerMouseDrag } from "./mouseDrag";
import { computerMouseMove } from "./mouseMove";
import { computerScreenInfo } from "./screenInfo";
import { computerScreenshot } from "./screenshot";
import { computerScroll } from "./scroll";
import { computerTypeText } from "./typeText";

/** All computer-use tool names registered in the harness. */
export const COMPUTER_USE_TOOL_NAMES = [
  "computer_screenshot",
  "computer_mouse_click",
  "computer_mouse_double_click",
  "computer_mouse_move",
  "computer_mouse_drag",
  "computer_type_text",
  "computer_key_press",
  "computer_scroll",
  "computer_screen_info",
] as const;

export type ComputerUseToolName = (typeof COMPUTER_USE_TOOL_NAMES)[number];

/**
 * Create the full set of computer-use tools from a {@link ToolContext}. The OS
 * is resolved per tool call from `process.platform`.
 */
export function createComputerUseToolset(ctx: ToolContext) {
  return {
    computer_screenshot: computerScreenshot(ctx),
    computer_mouse_click: computerMouseClick(ctx),
    computer_mouse_double_click: computerMouseDoubleClick(ctx),
    computer_mouse_move: computerMouseMove(ctx),
    computer_mouse_drag: computerMouseDrag(ctx),
    computer_type_text: computerTypeText(ctx),
    computer_key_press: computerKeyPress(ctx),
    computer_scroll: computerScroll(ctx),
    computer_screen_info: computerScreenInfo(ctx),
  } as const;
}

export { localExec, resolveDesktopOs } from "./runtime";
export {
  computerKeyPress,
  computerMouseClick,
  computerMouseDoubleClick,
  computerMouseDrag,
  computerMouseMove,
  computerScreenInfo,
  computerScreenshot,
  computerScroll,
  computerTypeText,
};
