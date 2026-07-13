import type { CliRenderer } from "@opentui/core";
import { overlayThemeRef } from "./console-theme";

/** Set up clipboard copying (OSC52 + native) and the notification overlay. */
export function createClipboardManager(renderer: CliRenderer) {
  let clipboardNotifExpiry = 0;

  const copyToClipboard = (text: string) => {
    renderer.copyToClipboardOSC52(text);
    try {
      // Suppress child stdio — xclip errors (e.g. "Can't open display" on
      // headless systems) would otherwise print over the TUI.
      const proc = Bun.spawn(
        process.platform === "darwin"
          ? ["pbcopy"]
          : ["xclip", "-selection", "clipboard"],
        { stdin: "pipe", stdout: "ignore", stderr: "ignore" },
      );
      proc.stdin.write(text);
      proc.stdin.end();
    } catch {
      // native clipboard command unavailable
    }
    clipboardNotifExpiry = Date.now() + 2000;
    renderer.requestRender();
    setTimeout(() => renderer.requestRender(), 2010);
  };

  const notifLabel = "Copied to clipboard";
  const notifPadX = 1;
  const notifBoxWidth = 1 + notifPadX + notifLabel.length + notifPadX + 1;
  const notifBoxHeight = 3;
  const notifMargin = 1;
  renderer.addPostProcessFn((buffer) => {
    if (Date.now() < clipboardNotifExpiry && overlayThemeRef.current) {
      const c = overlayThemeRef.current;
      const x = buffer.width - notifBoxWidth - notifMargin;
      const y = notifMargin;
      buffer.fillRect(x, y, notifBoxWidth, notifBoxHeight, c.backgroundElement);
      buffer.drawBox({
        x,
        y,
        width: notifBoxWidth,
        height: notifBoxHeight,
        border: true,
        borderColor: c.border,
        backgroundColor: c.backgroundElement,
        shouldFill: false,
      });
      buffer.drawText(
        notifLabel,
        x + 1 + notifPadX,
        y + 1,
        c.text,
        c.backgroundElement,
      );
      // Don't call renderer.requestRender() here — post-process functions
      // run during each render pass, causing an infinite loop.
    }
  });

  renderer.console.onCopySelection = copyToClipboard;

  return { copyToClipboard };
}
