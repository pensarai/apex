import type { CliRenderer } from "@opentui/core";
import { overlayThemeRef } from "./console-theme";

/** Set up clipboard copying (OSC52 + native) and the notification overlay. */
export function createClipboardManager(renderer: CliRenderer) {
  let clipboardNotifExpiry = 0;

  const copyToClipboard = (text: string) => {
    renderer.copyToClipboardOSC52(text);
    try {
      const proc = Bun.spawn(
        process.platform === "darwin"
          ? ["pbcopy"]
          : ["xclip", "-selection", "clipboard"],
        { stdin: "pipe" },
      );
      proc.stdin.write(text);
      proc.stdin.end();
    } catch {
      // Clipboard command unavailable
    }
    // Show "Copied to clipboard" notification for 2 seconds
    clipboardNotifExpiry = Date.now() + 2000;
    renderer.requestRender();
    setTimeout(() => renderer.requestRender(), 2010);
  };

  // Draw the "Copied to clipboard" overlay in the top-right corner
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
      // NOTE: Do NOT call renderer.requestRender() here — post-process
      // functions run during each render pass, so it would create an
      // infinite render loop. The copyToClipboard function already triggers
      // the initial render + a setTimeout for the cleanup render.
    }
  });

  // Wire up console copy to system clipboard
  renderer.console.onCopySelection = copyToClipboard;

  return { copyToClipboard };
}
