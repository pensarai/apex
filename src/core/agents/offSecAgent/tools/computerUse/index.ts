/**
 * Computer Use tools — desktop automation via xdotool (Linux), cliclick (macOS),
 * and PowerShell/.NET (Windows).
 *
 * Provides low-level desktop interaction primitives: screenshot, mouse clicks,
 * keyboard input, scrolling, and drag operations. These tools enable agents
 * to interact with graphical applications for penetration testing scenarios
 * that require GUI interaction (e.g. thick-client apps, VNC sessions, RDP).
 *
 * The tools are platform-aware:
 * - Linux: xdotool + scrot/ImageMagick
 * - macOS: cliclick + screencapture
 * - Windows: PowerShell + .NET System.Windows.Forms / user32.dll
 */

import type { ToolContext } from "../types";
import { computerScreenshot } from "./screenshot";
import { computerMouseClick } from "./mouseClick";
import { computerMouseDoubleClick } from "./mouseDoubleClick";
import { computerMouseMove } from "./mouseMove";
import { computerMouseDrag } from "./mouseDrag";
import { computerTypeText } from "./typeText";
import { computerKeyPress } from "./keyPress";
import { computerScroll } from "./scroll";
import { computerScreenInfo } from "./screenInfo";

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

export {
  computerScreenshot,
  computerMouseClick,
  computerMouseDoubleClick,
  computerMouseMove,
  computerMouseDrag,
  computerTypeText,
  computerKeyPress,
  computerScroll,
  computerScreenInfo,
};

export { type DesktopBackend, type Platform, detectPlatform } from "./platform";
