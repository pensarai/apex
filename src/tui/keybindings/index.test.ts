import { describe, expect, it } from "vitest";
import { matchesKeybind, parseKeybind } from "./match";

function questionMarkBinding() {
  const binding = parseKeybind("?")[0];
  if (!binding) throw new Error("Question-mark binding did not parse");
  return binding;
}

describe("matchesKeybind", () => {
  it("matches printable punctuation reported with Kitty shift metadata", () => {
    const questionMark = questionMarkBinding();

    expect(
      matchesKeybind(
        {
          name: "?",
          sequence: "?",
          ctrl: false,
          meta: false,
          shift: true,
          super: false,
        },
        questionMark,
      ),
    ).toBe(true);
  });

  it("does not confuse the unshifted slash key with question mark", () => {
    const questionMark = questionMarkBinding();

    expect(
      matchesKeybind(
        {
          name: "/",
          sequence: "/",
          ctrl: false,
          meta: false,
          shift: false,
          super: false,
        },
        questionMark,
      ),
    ).toBe(false);
  });
});
