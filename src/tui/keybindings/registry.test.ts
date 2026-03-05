import { describe, expect, it, vi } from "vitest";
import { createKeybindings, type KeybindingDependencies } from "./registry";
import { resolveKeybinding, type KeybindingRuntimeContext } from "./system";
import type { KeybindInfo } from "./parser";

function createDeps(): KeybindingDependencies {
  return {
    refocusPrompt: vi.fn(),
    ctrlCPressTime: null,
    setCtrlCPressTime: vi.fn(),
    setShowExitWarning: vi.fn(),
    setInputKey: vi.fn(),
    setShowSessionsDialog: vi.fn(),
    setShowShortcutsDialog: vi.fn(),
    setExternalDialogOpen: vi.fn(),
    setFocusIndex: vi.fn(),
    navigableItems: ["command-input"],
    setShowToolsPanel: vi.fn(),
  };
}

function runtimeContext(
  overrides: Partial<KeybindingRuntimeContext> = {},
): KeybindingRuntimeContext {
  return {
    routeType: "base",
    routePath: "home",
    dialogStackDepth: 0,
    externalDialogOpen: false,
    isPromptFocused: true,
    promptValue: "",
    ...overrides,
  };
}

function key(name: string, overrides: Partial<KeybindInfo> = {}): KeybindInfo {
  return {
    name,
    ctrl: false,
    shift: false,
    meta: false,
    super: false,
    sequence: undefined,
    ...overrides,
  };
}

describe("createKeybindings + resolveKeybinding", () => {
  it("resolves ctrl+s only on home route", () => {
    const registry = createKeybindings(createDeps());
    const pressed = key("s", { ctrl: true });

    const homeMatch = resolveKeybinding(
      registry,
      pressed,
      runtimeContext({ routePath: "home" }),
    );
    const providersMatch = resolveKeybinding(
      registry,
      pressed,
      runtimeContext({ routePath: "providers" }),
    );

    expect(homeMatch?.id).toBe("show-sessions");
    expect(providersMatch).toBeNull();
  });

  it("resolves ? only when prompt is focused and empty", () => {
    const registry = createKeybindings(createDeps());
    const pressed = key("?");

    const emptyMatch = resolveKeybinding(
      registry,
      pressed,
      runtimeContext({ isPromptFocused: true, promptValue: "" }),
    );
    const nonEmptyMatch = resolveKeybinding(
      registry,
      pressed,
      runtimeContext({ isPromptFocused: true, promptValue: "hello" }),
    );
    const unfocusedMatch = resolveKeybinding(
      registry,
      pressed,
      runtimeContext({ isPromptFocused: false, promptValue: "" }),
    );

    expect(emptyMatch?.id).toBe("show-shortcuts-dialog");
    expect(nonEmptyMatch).toBeNull();
    expect(unfocusedMatch).toBeNull();
  });

  it("resolves shift+tab only in prompt-sensitive context", () => {
    const registry = createKeybindings(createDeps());
    const pressed = key("tab", { shift: true });

    const emptyMatch = resolveKeybinding(
      registry,
      pressed,
      runtimeContext({ isPromptFocused: true, promptValue: "" }),
    );
    const nonEmptyMatch = resolveKeybinding(
      registry,
      pressed,
      runtimeContext({ isPromptFocused: true, promptValue: "x" }),
    );

    expect(emptyMatch?.id).toBe("focus-previous-item");
    expect(nonEmptyMatch).toBeNull();
  });
});
