import type { CliRenderer } from "@opentui/core";

/** Wire up auto-copy-on-select for both the console pane and the main app. */
export function setupAutoCopy(
  renderer: CliRenderer,
  copyToClipboard: (text: string) => void,
): () => void {
  // biome-ignore lint/suspicious/noExplicitAny: opentui CliRenderer.console is loosely typed and exposes runtime hooks not in its public type.
  (renderer.console as any).getCopyButtonLabel = () => "Select to copy";

  const originalHandleMouse = renderer.console.handleMouse.bind(
    renderer.console,
  );
  renderer.console.handleMouse = (event) => {
    const result = originalHandleMouse(event);
    if (event.type === "up") {
      // biome-ignore lint/suspicious/noExplicitAny: opentui CliRenderer.console is loosely typed and exposes runtime hooks not in its public type.
      const c = renderer.console as any;
      if (typeof c.hasSelection === "function" && c.hasSelection()) {
        c.triggerCopy();
      }
    }
    return result;
  };

  // biome-ignore lint/suspicious/noExplicitAny: opentui selection event payload is not exported from its public type.
  const handleSelection = (selection: any) => {
    if (selection && !selection.isDragging) {
      const text = selection.getSelectedText();
      if (text) {
        copyToClipboard(text);
      }
      process.nextTick(() => renderer.clearSelection());
    }
  };
  renderer.on("selection", handleSelection);

  let cleaned = false;
  return () => {
    if (cleaned) return;
    cleaned = true;
    renderer.off("selection", handleSelection);
    renderer.console.handleMouse = originalHandleMouse;
  };
}
