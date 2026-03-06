import { describe, expect, it } from "vitest";
import {
  filterSuggestions,
  resolveSubmitValue,
  computeUpArrow,
  computeDownArrow,
  computeTab,
  shouldResetHistory,
  type NavState,
} from "./prompt-input-logic";
import type { AutocompleteOption } from "./prompt-input";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const options: AutocompleteOption[] = [
  { value: "/scan", label: "/scan", description: "Run a scan" },
  { value: "/pentest", label: "/pentest", description: "Run a pentest" },
  { value: "/help", label: "/help", description: "Show help" },
  { value: "/session", label: "/session", description: "Session info" },
  { value: "/settings", label: "/settings", description: "Open settings" },
];

const history = ["first cmd", "second cmd", "third cmd"];

// ---------------------------------------------------------------------------
// filterSuggestions
// ---------------------------------------------------------------------------

describe("filterSuggestions", () => {
  it("returns empty for empty input", () => {
    expect(filterSuggestions("", options, 10)).toEqual([]);
  });

  it("returns empty for input without leading /", () => {
    expect(filterSuggestions("scan", options, 10)).toEqual([]);
  });

  it("returns all options matching /", () => {
    const result = filterSuggestions("/", options, 10);
    expect(result).toHaveLength(5);
  });

  it("filters by value substring", () => {
    const result = filterSuggestions("/sc", options, 10);
    expect(result).toHaveLength(1);
    expect(result[0]!.value).toBe("/scan");
  });

  it("filters by label substring", () => {
    const result = filterSuggestions("/pen", options, 10);
    expect(result).toHaveLength(1);
    expect(result[0]!.value).toBe("/pentest");
  });

  it("is case-insensitive", () => {
    const result = filterSuggestions("/HELP", options, 10);
    expect(result).toHaveLength(1);
    expect(result[0]!.value).toBe("/help");
  });

  it("respects maxSuggestions", () => {
    const result = filterSuggestions("/s", options, 2);
    expect(result).toHaveLength(2);
  });

  it("matches multiple options with shared substring", () => {
    const result = filterSuggestions("/se", options, 10);
    expect(result.map((s) => s.value)).toEqual(["/session", "/settings"]);
  });

  it("returns empty for no matches", () => {
    expect(filterSuggestions("/zzz", options, 10)).toEqual([]);
  });

  it("returns empty for empty options array", () => {
    expect(filterSuggestions("/scan", [], 10)).toEqual([]);
  });

  it("trims whitespace from input", () => {
    const result = filterSuggestions("  /scan  ", options, 10);
    expect(result).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// resolveSubmitValue
// ---------------------------------------------------------------------------

describe("resolveSubmitValue", () => {
  it("returns selected suggestion value when valid index", () => {
    expect(resolveSubmitValue("typed text", options, 1)).toBe("/pentest");
  });

  it("returns trimmed raw text when no suggestions", () => {
    expect(resolveSubmitValue("  hello  ", [], -1)).toBe("hello");
  });

  it("returns trimmed raw text when selectedIndex is -1", () => {
    expect(resolveSubmitValue("  hello  ", options, -1)).toBe("hello");
  });

  it("returns trimmed raw text when selectedIndex is out of bounds", () => {
    expect(resolveSubmitValue("hello", options, 999)).toBe("hello");
  });

  it("returns empty string for whitespace-only raw text with no selection", () => {
    expect(resolveSubmitValue("   ", [], -1)).toBe("");
  });
});

// ---------------------------------------------------------------------------
// computeUpArrow
// ---------------------------------------------------------------------------

describe("computeUpArrow", () => {
  describe("when in autocomplete", () => {
    it("exits autocomplete when at top of suggestion list (index 0)", () => {
      const state: NavState = { historyIndex: -1, selectedSuggestionIndex: 0 };
      const result = computeUpArrow(state, history, 3);
      expect(result).not.toBeNull();
      expect(result!.nextState.selectedSuggestionIndex).toBe(-1);
      expect(result!.textToSet).toBeNull();
    });

    it("moves up within suggestion list", () => {
      const state: NavState = { historyIndex: -1, selectedSuggestionIndex: 2 };
      const result = computeUpArrow(state, history, 3);
      expect(result).not.toBeNull();
      expect(result!.nextState.selectedSuggestionIndex).toBe(1);
      expect(result!.textToSet).toBeNull();
    });
  });

  describe("when not in autocomplete", () => {
    it("returns null when history is empty", () => {
      const state: NavState = {
        historyIndex: -1,
        selectedSuggestionIndex: -1,
      };
      expect(computeUpArrow(state, [], 0)).toBeNull();
    });

    it("navigates to most recent history entry from current input", () => {
      const state: NavState = {
        historyIndex: -1,
        selectedSuggestionIndex: -1,
      };
      const result = computeUpArrow(state, history, 0);
      expect(result).not.toBeNull();
      expect(result!.nextState.historyIndex).toBe(0);
      expect(result!.textToSet).toBe("third cmd");
      expect(result!.saveCurrentInput).toBe(true);
    });

    it("navigates up through history entries", () => {
      const state: NavState = {
        historyIndex: 0,
        selectedSuggestionIndex: -1,
      };
      const result = computeUpArrow(state, history, 0);
      expect(result).not.toBeNull();
      expect(result!.nextState.historyIndex).toBe(1);
      expect(result!.textToSet).toBe("second cmd");
      expect(result!.saveCurrentInput).toBe(false);
    });

    it("clamps at the oldest history entry", () => {
      const state: NavState = {
        historyIndex: 2,
        selectedSuggestionIndex: -1,
      };
      const result = computeUpArrow(state, history, 0);
      expect(result).not.toBeNull();
      expect(result!.nextState.historyIndex).toBe(2);
      expect(result!.textToSet).toBe("first cmd");
    });

    it("marks saveCurrentInput only when entering history from -1", () => {
      const from0: NavState = {
        historyIndex: 0,
        selectedSuggestionIndex: -1,
      };
      expect(computeUpArrow(from0, history, 0)!.saveCurrentInput).toBe(false);

      const fromNeg: NavState = {
        historyIndex: -1,
        selectedSuggestionIndex: -1,
      };
      expect(computeUpArrow(fromNeg, history, 0)!.saveCurrentInput).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// computeDownArrow
// ---------------------------------------------------------------------------

describe("computeDownArrow", () => {
  describe("when in autocomplete with multiple suggestions", () => {
    it("moves down within suggestion list", () => {
      const state: NavState = { historyIndex: -1, selectedSuggestionIndex: 0 };
      const result = computeDownArrow(state, history, 3, "");
      expect(result).not.toBeNull();
      expect(result!.nextState.selectedSuggestionIndex).toBe(1);
      expect(result!.textToSet).toBeNull();
    });

    it("clamps at the last suggestion", () => {
      const state: NavState = { historyIndex: -1, selectedSuggestionIndex: 2 };
      const result = computeDownArrow(state, history, 3, "");
      expect(result).not.toBeNull();
      expect(result!.nextState.selectedSuggestionIndex).toBe(2);
    });
  });

  describe("when in autocomplete with single suggestion", () => {
    it("exits autocomplete and falls through to history", () => {
      const state: NavState = { historyIndex: -1, selectedSuggestionIndex: 0 };
      const result = computeDownArrow(state, history, 1, "saved");
      expect(result).not.toBeNull();
      expect(result!.nextState.selectedSuggestionIndex).toBe(-1);
    });

    it("exits autocomplete to history navigation when browsing history", () => {
      const state: NavState = { historyIndex: 1, selectedSuggestionIndex: 0 };
      const result = computeDownArrow(state, history, 1, "saved");
      expect(result).not.toBeNull();
      expect(result!.nextState.selectedSuggestionIndex).toBe(-1);
      expect(result!.nextState.historyIndex).toBe(0);
      expect(result!.textToSet).toBe("third cmd");
    });
  });

  describe("when not in autocomplete, no history", () => {
    it("overflows to autocomplete when multiple suggestions", () => {
      const state: NavState = {
        historyIndex: -1,
        selectedSuggestionIndex: -1,
      };
      const result = computeDownArrow(state, [], 3, "");
      expect(result).not.toBeNull();
      expect(result!.nextState.selectedSuggestionIndex).toBe(0);
    });

    it("returns null when single or no suggestions", () => {
      const state: NavState = {
        historyIndex: -1,
        selectedSuggestionIndex: -1,
      };
      expect(computeDownArrow(state, [], 1, "")).toBeNull();
      expect(computeDownArrow(state, [], 0, "")).toBeNull();
    });
  });

  describe("when not in autocomplete, with history", () => {
    it("navigates down through history entries", () => {
      const state: NavState = {
        historyIndex: 2,
        selectedSuggestionIndex: -1,
      };
      const result = computeDownArrow(state, history, 0, "saved");
      expect(result).not.toBeNull();
      expect(result!.nextState.historyIndex).toBe(1);
      expect(result!.textToSet).toBe("second cmd");
    });

    it("restores saved input when reaching bottom of history", () => {
      const state: NavState = {
        historyIndex: 0,
        selectedSuggestionIndex: -1,
      };
      const result = computeDownArrow(state, history, 0, "my saved input");
      expect(result).not.toBeNull();
      expect(result!.nextState.historyIndex).toBe(-1);
      expect(result!.textToSet).toBe("my saved input");
    });

    it("already at current input, overflows into autocomplete when multiple suggestions", () => {
      const state: NavState = {
        historyIndex: -1,
        selectedSuggestionIndex: -1,
      };
      const result = computeDownArrow(state, history, 3, "saved");
      expect(result).not.toBeNull();
      expect(result!.nextState.historyIndex).toBe(-1);
      expect(result!.nextState.selectedSuggestionIndex).toBe(0);
      expect(result!.textToSet).toBe("saved");
    });

    it("already at current input, does not overflow with single suggestion", () => {
      const state: NavState = {
        historyIndex: -1,
        selectedSuggestionIndex: -1,
      };
      const result = computeDownArrow(state, history, 1, "saved");
      expect(result).not.toBeNull();
      expect(result!.nextState.selectedSuggestionIndex).toBe(-1);
    });
  });
});

// ---------------------------------------------------------------------------
// computeTab
// ---------------------------------------------------------------------------

describe("computeTab", () => {
  it("returns null when no suggestions", () => {
    expect(computeTab([], 0)).toBeNull();
  });

  it("accepts the highlighted suggestion", () => {
    const result = computeTab(options, 2);
    expect(result).not.toBeNull();
    expect(result!.acceptedValue).toBe("/help");
    expect(result!.selectedSuggestionIndex).toBe(-1);
  });

  it("selects first suggestion when none is highlighted", () => {
    const result = computeTab(options, -1);
    expect(result).not.toBeNull();
    expect(result!.acceptedValue).toBeNull();
    expect(result!.selectedSuggestionIndex).toBe(0);
  });

  it("selects first suggestion when index is out of bounds", () => {
    const result = computeTab(options, 999);
    expect(result).not.toBeNull();
    expect(result!.acceptedValue).toBeNull();
    expect(result!.selectedSuggestionIndex).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// shouldResetHistory
// ---------------------------------------------------------------------------

describe("shouldResetHistory", () => {
  it("returns true when browsing history and not navigating programmatically", () => {
    expect(shouldResetHistory(2, false)).toBe(true);
  });

  it("returns false when not browsing history (index -1)", () => {
    expect(shouldResetHistory(-1, false)).toBe(false);
  });

  it("returns false when navigating programmatically", () => {
    expect(shouldResetHistory(2, true)).toBe(false);
  });

  it("returns false when both at -1 and navigating", () => {
    expect(shouldResetHistory(-1, true)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Integration-style scenarios: full navigation sequences
// ---------------------------------------------------------------------------

describe("navigation sequences", () => {
  it("up through entire history and back down restores saved input", () => {
    let state: NavState = { historyIndex: -1, selectedSuggestionIndex: -1 };
    const savedInput = "my draft";

    // Go up through all 3 history entries
    const up1 = computeUpArrow(state, history, 0)!;
    expect(up1.textToSet).toBe("third cmd");
    expect(up1.saveCurrentInput).toBe(true);
    state = up1.nextState;

    const up2 = computeUpArrow(state, history, 0)!;
    expect(up2.textToSet).toBe("second cmd");
    state = up2.nextState;

    const up3 = computeUpArrow(state, history, 0)!;
    expect(up3.textToSet).toBe("first cmd");
    state = up3.nextState;

    // Clamp at top
    const up4 = computeUpArrow(state, history, 0)!;
    expect(up4.textToSet).toBe("first cmd");
    expect(up4.nextState.historyIndex).toBe(2);
    state = up4.nextState;

    // Go all the way back down
    const down1 = computeDownArrow(state, history, 0, savedInput)!;
    expect(down1.textToSet).toBe("second cmd");
    state = down1.nextState;

    const down2 = computeDownArrow(state, history, 0, savedInput)!;
    expect(down2.textToSet).toBe("third cmd");
    state = down2.nextState;

    const down3 = computeDownArrow(state, history, 0, savedInput)!;
    expect(down3.textToSet).toBe(savedInput);
    expect(down3.nextState.historyIndex).toBe(-1);
  });

  it("history bottom → autocomplete overflow → up exits autocomplete", () => {
    let state: NavState = { historyIndex: -1, selectedSuggestionIndex: -1 };

    // Down at bottom with multiple suggestions → overflow to autocomplete
    const down1 = computeDownArrow(state, history, 3, "saved")!;
    expect(down1.nextState.selectedSuggestionIndex).toBe(0);
    state = down1.nextState;

    // Up exits autocomplete
    const up1 = computeUpArrow(state, history, 3)!;
    expect(up1.nextState.selectedSuggestionIndex).toBe(-1);
    expect(up1.textToSet).toBeNull();
  });

  it("single suggestion does not trap down arrow navigation", () => {
    // Start in autocomplete with 1 suggestion + at history index 1
    const state: NavState = { historyIndex: 1, selectedSuggestionIndex: 0 };

    const result = computeDownArrow(state, history, 1, "saved")!;
    // Should exit autocomplete and navigate history down
    expect(result.nextState.selectedSuggestionIndex).toBe(-1);
    expect(result.nextState.historyIndex).toBe(0);
    expect(result.textToSet).toBe("third cmd");
  });
});
