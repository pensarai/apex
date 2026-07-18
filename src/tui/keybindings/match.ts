import type { ParsedKey } from "@opentui/core";

export type KeybindInfo = Pick<
  ParsedKey,
  "name" | "ctrl" | "meta" | "shift" | "super"
> & {
  sequence?: string;
};

export function fromParsedKey(key: ParsedKey, _leader = false): KeybindInfo {
  return {
    name: key.name,
    ctrl: key.ctrl,
    meta: key.meta,
    shift: key.shift,
    super: key.super ?? false,
    sequence: key.sequence,
  };
}

export function parseKeybind(key: string): KeybindInfo[] {
  if (key === "none") return [];

  return key.split(",").map((c) => {
    const parts = c.split("+");

    const info: KeybindInfo = {
      ctrl: false,
      meta: false,
      shift: false,
      name: "",
      sequence: undefined,
    };

    for (const part of parts) {
      const lowerPart = part.toLowerCase();
      switch (lowerPart) {
        case "ctrl":
          info.ctrl = true;
          break;
        case "alt":
        case "meta":
        case "option":
          info.meta = true;
          break;
        case "super":
          info.super = true;
          break;
        case "shift":
          info.shift = true;
          break;
        case "esc":
          info.name = "escape";
          break;
        default:
          if (part.length === 1 && part !== lowerPart) {
            info.sequence = part;
          } else {
            info.name = lowerPart;
          }
          break;
      }
    }

    return info;
  });
}

export function matchesKeybind(
  pressed: KeybindInfo,
  combo: KeybindInfo,
): boolean {
  const isUnmodifiedPrintableCombo =
    combo.name.length === 1 &&
    !combo.ctrl &&
    !combo.meta &&
    !combo.shift &&
    !(combo.super ?? false);
  if (
    isUnmodifiedPrintableCombo &&
    pressed.sequence === combo.name &&
    !pressed.ctrl &&
    !pressed.meta &&
    !(pressed.super ?? false)
  ) {
    return true;
  }

  if (combo.sequence) {
    return (
      pressed.sequence === combo.sequence &&
      pressed.ctrl === combo.ctrl &&
      pressed.meta === combo.meta &&
      (pressed.super ?? false) === (combo.super ?? false)
    );
  }

  if (combo.ctrl && combo.name && pressed.sequence) {
    const charCode = pressed.sequence.charCodeAt(0);
    if (charCode >= 1 && charCode <= 26) {
      const expectedChar = String.fromCharCode(charCode + 96);
      if (combo.name === expectedChar) {
        return (
          pressed.meta === combo.meta &&
          (pressed.super ?? false) === (combo.super ?? false)
        );
      }
    }
  }

  return (
    pressed.name === combo.name &&
    pressed.ctrl === combo.ctrl &&
    pressed.meta === combo.meta &&
    pressed.shift === combo.shift &&
    (pressed.super ?? false) === (combo.super ?? false)
  );
}
