import { keybindToString, matchesKeybind, parseKeybind, type KeybindInfo } from "./parser";

export type KeybindingScope = "global" | "prompt" | "dialog" | "session";

export interface KeybindingRuntimeContext {
  routeType: "base" | "pentest" | "operator";
  routePath?: string;
  dialogStackDepth: number;
  externalDialogOpen: boolean;
  isPromptFocused: boolean;
  promptValue: string;
}

export interface KeybindingDefinition<ActionContext> {
  id: string;
  combo: string;
  description: string;
  handler: (context: ActionContext) => Promise<void> | void;
  scope?: KeybindingScope;
  priority?: number;
  when?: (context: KeybindingRuntimeContext) => boolean;
}

export interface RegisteredKeybinding<ActionContext>
  extends Omit<KeybindingDefinition<ActionContext>, "scope" | "priority" | "when"> {
  scope: KeybindingScope;
  priority: number;
  when: (context: KeybindingRuntimeContext) => boolean;
  parsedCombos: KeybindInfo[];
}

export interface KeybindingRegistry<ActionContext> {
  register: (
    definition: KeybindingDefinition<ActionContext>,
  ) => RegisteredKeybinding<ActionContext>;
  list: () => RegisteredKeybinding<ActionContext>[];
}

export function registerKeybinding<ActionContext>(
  registry: RegisteredKeybinding<ActionContext>[],
  definition: KeybindingDefinition<ActionContext>,
): RegisteredKeybinding<ActionContext> {
  const registered: RegisteredKeybinding<ActionContext> = {
    ...definition,
    scope: definition.scope ?? "global",
    priority: definition.priority ?? 0,
    when: definition.when ?? (() => true),
    parsedCombos: parseKeybind(definition.combo),
  };
  registry.push(registered);
  return registered;
}

export function createKeybindingRegistry<ActionContext>(): KeybindingRegistry<ActionContext> {
  const entries: RegisteredKeybinding<ActionContext>[] = [];
  return {
    register: (definition) => registerKeybinding(entries, definition),
    list: () =>
      [...entries].sort((a, b) => {
        if (a.priority !== b.priority) {
          return b.priority - a.priority;
        }
        return a.id.localeCompare(b.id);
      }),
  };
}

export function resolveKeybinding<ActionContext>(
  bindings: RegisteredKeybinding<ActionContext>[],
  pressedKey: KeybindInfo,
  runtimeContext: KeybindingRuntimeContext,
): RegisteredKeybinding<ActionContext> | null {
  for (const binding of bindings) {
    if (!binding.when(runtimeContext)) {
      continue;
    }

    for (const combo of binding.parsedCombos) {
      if (matchesKeybind(pressedKey, combo)) {
        return binding;
      }
    }
  }

  return null;
}

const DISPLAY_TOKEN_MAP: Record<string, string> = {
  ctrl: "Ctrl",
  shift: "Shift",
  alt: "Alt",
  meta: "Alt",
  option: "Alt",
  super: "Super",
  esc: "Esc",
  escape: "Esc",
};

export function formatKeybindingCombo(combo: string): string {
  const parts = parseKeybind(combo);
  if (parts.length === 0) {
    return combo;
  }

  return parts
    .map((part) => {
      const display = keybindToString(part);
      if (!display) return combo;
      return display
        .split("+")
        .map((token) => {
          const mapped = DISPLAY_TOKEN_MAP[token];
          if (mapped) {
            return mapped;
          }
          if (token.length === 1) {
            return token.toUpperCase();
          }
          return token.charAt(0).toUpperCase() + token.slice(1);
        })
        .join("+");
    })
    .join(", ");
}
