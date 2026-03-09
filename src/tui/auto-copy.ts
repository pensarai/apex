import type { CliRenderer } from "@opentui/core";

/** Wire up auto-copy-on-select for both the console pane and the main app. */
export function setupAutoCopy(
  renderer: CliRenderer,
  copyToClipboard: (text: string) => void,
) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (renderer.console as any).getCopyButtonLabel = () => "Select to copy";

  const originalHandleMouse = renderer.console.handleMouse.bind(
    renderer.console,
  );
  renderer.console.handleMouse = (event) => {
    const result = originalHandleMouse(event);
    if (event.type === "up") {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const c = renderer.console as any;
      if (typeof c.hasSelection === "function" && c.hasSelection()) {
        c.triggerCopy();
      }
    }
    return result;
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  renderer.on("selection", (selection: any) => {
    if (selection && !selection.isDragging) {
      const text = selection.getSelectedText();
      if (text) {
        copyToClipboard(text);
      }
      process.nextTick(() => renderer.clearSelection());
    }
  });
}
