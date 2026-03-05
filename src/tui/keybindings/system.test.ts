import { describe, expect, it, vi } from "vitest";
import {
  createKeybindingRegistry,
  resolveKeybinding,
  type KeybindingRuntimeContext,
} from "./system";
import type { KeybindInfo } from "./parser";

const baseRuntimeContext: KeybindingRuntimeContext = {
  routeType: "base",
  routePath: "home",
  dialogStackDepth: 0,
  externalDialogOpen: false,
  isPromptFocused: true,
  promptValue: "",
};

const ctrlS: KeybindInfo = {
  name: "s",
  ctrl: true,
  shift: false,
  meta: false,
  super: false,
};

describe("keybinding registration API", () => {
  it("registers through one registry API and resolves by priority", () => {
    const high = vi.fn();
    const low = vi.fn();
    const registry = createKeybindingRegistry<{ handled: string }>();

    registry.register({
      id: "low-priority",
      combo: "ctrl+s",
      description: "Low priority",
      priority: 1,
      handler: low,
    });
    registry.register({
      id: "high-priority",
      combo: "ctrl+s",
      description: "High priority",
      priority: 10,
      handler: high,
    });

    const match = resolveKeybinding(registry.list(), ctrlS, baseRuntimeContext);
    expect(match?.id).toBe("high-priority");
  });
});
