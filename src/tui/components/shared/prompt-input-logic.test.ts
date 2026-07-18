import { describe, expect, it } from "vitest";
import type { AutocompleteOption } from "./prompt-input";
import {
  computeDownArrow,
  computeInlineCompletion,
  computeTab,
  computeUpArrow,
  computeVisibleWindow,
  detectInlineOption,
  detectInlineSlash,
  filterInlineOptionSuggestions,
  filterInlineSuggestions,
  type NavState,
  shouldNavigateHistory,
  shouldResetHistory,
} from "./prompt-input-logic";

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

describe("shouldNavigateHistory", () => {
  it("keeps arrow keys in the textarea between visual boundaries", () => {
    expect(shouldNavigateHistory("up", 1, 0, 3)).toBe(false);
    expect(shouldNavigateHistory("down", 1, 0, 3)).toBe(false);
  });

  it("allows history at the first and last visual lines", () => {
    expect(shouldNavigateHistory("up", 0, 0, 3)).toBe(true);
    expect(shouldNavigateHistory("down", 2, 0, 3)).toBe(true);
  });

  it("accounts for a scrolled textarea viewport", () => {
    expect(shouldNavigateHistory("up", 0, 2, 6)).toBe(false);
    expect(shouldNavigateHistory("down", 2, 3, 6)).toBe(true);
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
      expect(result?.nextState.selectedSuggestionIndex).toBe(-1);
      expect(result?.textToSet).toBeNull();
    });

    it("moves up within suggestion list", () => {
      const state: NavState = { historyIndex: -1, selectedSuggestionIndex: 2 };
      const result = computeUpArrow(state, history, 3);
      expect(result).not.toBeNull();
      expect(result?.nextState.selectedSuggestionIndex).toBe(1);
      expect(result?.textToSet).toBeNull();
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
      expect(result?.nextState.historyIndex).toBe(0);
      expect(result?.textToSet).toBe("third cmd");
      expect(result?.saveCurrentInput).toBe(true);
    });

    it("navigates up through history entries", () => {
      const state: NavState = {
        historyIndex: 0,
        selectedSuggestionIndex: -1,
      };
      const result = computeUpArrow(state, history, 0);
      expect(result).not.toBeNull();
      expect(result?.nextState.historyIndex).toBe(1);
      expect(result?.textToSet).toBe("second cmd");
      expect(result?.saveCurrentInput).toBe(false);
    });

    it("clamps at the oldest history entry", () => {
      const state: NavState = {
        historyIndex: 2,
        selectedSuggestionIndex: -1,
      };
      const result = computeUpArrow(state, history, 0);
      expect(result).not.toBeNull();
      expect(result?.nextState.historyIndex).toBe(2);
      expect(result?.textToSet).toBe("first cmd");
    });

    it("marks saveCurrentInput only when entering history from -1", () => {
      const from0: NavState = {
        historyIndex: 0,
        selectedSuggestionIndex: -1,
      };
      expect(computeUpArrow(from0, history, 0)?.saveCurrentInput).toBe(false);

      const fromNeg: NavState = {
        historyIndex: -1,
        selectedSuggestionIndex: -1,
      };
      expect(computeUpArrow(fromNeg, history, 0)?.saveCurrentInput).toBe(true);
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
      expect(result?.nextState.selectedSuggestionIndex).toBe(1);
      expect(result?.textToSet).toBeNull();
    });

    it("clamps at the last suggestion", () => {
      const state: NavState = { historyIndex: -1, selectedSuggestionIndex: 2 };
      const result = computeDownArrow(state, history, 3, "");
      expect(result).not.toBeNull();
      expect(result?.nextState.selectedSuggestionIndex).toBe(2);
    });
  });

  describe("when in autocomplete with single suggestion", () => {
    it("exits autocomplete and falls through to history", () => {
      const state: NavState = { historyIndex: -1, selectedSuggestionIndex: 0 };
      const result = computeDownArrow(state, history, 1, "saved");
      expect(result).not.toBeNull();
      expect(result?.nextState.selectedSuggestionIndex).toBe(-1);
    });

    it("exits autocomplete to history navigation when browsing history", () => {
      const state: NavState = { historyIndex: 1, selectedSuggestionIndex: 0 };
      const result = computeDownArrow(state, history, 1, "saved");
      expect(result).not.toBeNull();
      expect(result?.nextState.selectedSuggestionIndex).toBe(-1);
      expect(result?.nextState.historyIndex).toBe(0);
      expect(result?.textToSet).toBe("third cmd");
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
      expect(result?.nextState.selectedSuggestionIndex).toBe(0);
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
      expect(result?.nextState.historyIndex).toBe(1);
      expect(result?.textToSet).toBe("second cmd");
    });

    it("restores saved input when reaching bottom of history", () => {
      const state: NavState = {
        historyIndex: 0,
        selectedSuggestionIndex: -1,
      };
      const result = computeDownArrow(state, history, 0, "my saved input");
      expect(result).not.toBeNull();
      expect(result?.nextState.historyIndex).toBe(-1);
      expect(result?.textToSet).toBe("my saved input");
    });

    it("already at current input, overflows into autocomplete when multiple suggestions", () => {
      const state: NavState = {
        historyIndex: -1,
        selectedSuggestionIndex: -1,
      };
      const result = computeDownArrow(state, history, 3, "saved");
      expect(result).not.toBeNull();
      expect(result?.nextState.historyIndex).toBe(-1);
      expect(result?.nextState.selectedSuggestionIndex).toBe(0);
      expect(result?.textToSet).toBe("saved");
    });

    it("already at current input, does not overflow with single suggestion", () => {
      const state: NavState = {
        historyIndex: -1,
        selectedSuggestionIndex: -1,
      };
      const result = computeDownArrow(state, history, 1, "saved");
      expect(result).not.toBeNull();
      expect(result?.nextState.selectedSuggestionIndex).toBe(-1);
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
    expect(result?.acceptedValue).toBe("/help");
    expect(result?.selectedSuggestionIndex).toBe(-1);
  });

  it("selects first suggestion when none is highlighted", () => {
    const result = computeTab(options, -1);
    expect(result).not.toBeNull();
    expect(result?.acceptedValue).toBeNull();
    expect(result?.selectedSuggestionIndex).toBe(0);
  });

  it("selects first suggestion when index is out of bounds", () => {
    const result = computeTab(options, 999);
    expect(result).not.toBeNull();
    expect(result?.acceptedValue).toBeNull();
    expect(result?.selectedSuggestionIndex).toBe(0);
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

// computeVisibleWindow
// ---------------------------------------------------------------------------

describe("computeVisibleWindow", () => {
  const makeSuggestions = (count: number): AutocompleteOption[] => {
    return Array.from({ length: count }, (_, i) => ({
      value: `/cmd${i}`,
      label: `/cmd${i}`,
      description: `Command ${i}`,
    }));
  };

  it("returns empty window for empty suggestions", () => {
    const result = computeVisibleWindow([], 0, 5);
    expect(result).toEqual({
      start: 0,
      end: 0,
      visibleSuggestions: [],
      hasMore: false,
      hasMoreBelow: false,
    });
  });

  it("shows all suggestions when count <= maxVisible", () => {
    const suggestions = makeSuggestions(3);
    const result = computeVisibleWindow(suggestions, 0, 5);
    expect(result.start).toBe(0);
    expect(result.end).toBe(3);
    expect(result.visibleSuggestions).toHaveLength(3);
    expect(result.hasMore).toBe(false);
    expect(result.hasMoreBelow).toBe(false);
  });

  it("shows windowed view when count > maxVisible", () => {
    const suggestions = makeSuggestions(10);
    const result = computeVisibleWindow(suggestions, 0, 5);
    expect(result.visibleSuggestions).toHaveLength(5);
    expect(result.start).toBe(0);
    expect(result.end).toBe(5);
    expect(result.hasMore).toBe(false);
    expect(result.hasMoreBelow).toBe(true);
  });

  it("centers window around selected index", () => {
    const suggestions = makeSuggestions(10);
    const result = computeVisibleWindow(suggestions, 5, 5);
    // With maxVisible=5, centering on index 5 should show indices 3-7
    expect(result.start).toBe(3);
    expect(result.end).toBe(8);
    expect(result.visibleSuggestions).toHaveLength(5);
    expect(result.hasMore).toBe(true);
    expect(result.hasMoreBelow).toBe(true);
  });

  it("adjusts window to start when selected is near beginning", () => {
    const suggestions = makeSuggestions(10);
    const result = computeVisibleWindow(suggestions, 1, 5);
    // Should show 0-4 (can't center around 1 without going negative)
    expect(result.start).toBe(0);
    expect(result.end).toBe(5);
    expect(result.hasMore).toBe(false);
    expect(result.hasMoreBelow).toBe(true);
  });

  it("adjusts window to end when selected is near bottom", () => {
    const suggestions = makeSuggestions(10);
    const result = computeVisibleWindow(suggestions, 8, 5);
    // Should show 5-9 (last 5 items)
    expect(result.start).toBe(5);
    expect(result.end).toBe(10);
    expect(result.hasMore).toBe(true);
    expect(result.hasMoreBelow).toBe(false);
  });

  it("handles selectedIndex of -1 (no selection)", () => {
    const suggestions = makeSuggestions(10);
    const result = computeVisibleWindow(suggestions, -1, 5);
    // Should show first 5 items when no selection
    expect(result.start).toBe(0);
    expect(result.end).toBe(5);
    expect(result.visibleSuggestions).toHaveLength(5);
  });

  it("correctly identifies scroll indicators", () => {
    const suggestions = makeSuggestions(15);

    // At the top
    const top = computeVisibleWindow(suggestions, 0, 5);
    expect(top.hasMore).toBe(false);
    expect(top.hasMoreBelow).toBe(true);

    // In the middle
    const middle = computeVisibleWindow(suggestions, 7, 5);
    expect(middle.hasMore).toBe(true);
    expect(middle.hasMoreBelow).toBe(true);

    // At the bottom
    const bottom = computeVisibleWindow(suggestions, 14, 5);
    expect(bottom.hasMore).toBe(true);
    expect(bottom.hasMoreBelow).toBe(false);
  });

  it("returns correct visible suggestions slice", () => {
    const suggestions = makeSuggestions(10);
    const result = computeVisibleWindow(suggestions, 5, 5);
    // Should return indices 3-7
    expect(result.visibleSuggestions[0]?.value).toBe("/cmd3");
    expect(result.visibleSuggestions[4]?.value).toBe("/cmd7");
  });

  it("handles maxVisible of 1", () => {
    const suggestions = makeSuggestions(10);
    const result = computeVisibleWindow(suggestions, 5, 1);
    expect(result.start).toBe(5);
    expect(result.end).toBe(6);
    expect(result.visibleSuggestions).toHaveLength(1);
    expect(result.visibleSuggestions[0]?.value).toBe("/cmd5");
  });

  it("handles maxVisible larger than suggestions", () => {
    const suggestions = makeSuggestions(3);
    const result = computeVisibleWindow(suggestions, 1, 10);
    expect(result.start).toBe(0);
    expect(result.end).toBe(3);
    expect(result.visibleSuggestions).toHaveLength(3);
    expect(result.hasMore).toBe(false);
    expect(result.hasMoreBelow).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// detectInlineSlash
// ---------------------------------------------------------------------------

describe("detectInlineSlash", () => {
  it("detects / at start of text", () => {
    expect(detectInlineSlash("/", 1)).toEqual({
      token: "/",
      start: 0,
      end: 1,
    });
  });

  it("detects partial slug at start of text", () => {
    expect(detectInlineSlash("/sc", 3)).toEqual({
      token: "/sc",
      start: 0,
      end: 3,
    });
  });

  it("detects inline / after space", () => {
    expect(detectInlineSlash("scan this /", 11)).toEqual({
      token: "/",
      start: 10,
      end: 11,
    });
  });

  it("detects inline partial slug", () => {
    expect(detectInlineSlash("scan this /vuln", 15)).toEqual({
      token: "/vuln",
      start: 10,
      end: 15,
    });
  });

  it("returns null when cursor is after a space following /", () => {
    // "scan / " with cursor at 7 (after the space)
    expect(detectInlineSlash("scan / ", 7)).toBeNull();
  });

  it("returns null when / is not preceded by whitespace", () => {
    expect(detectInlineSlash("http://foo", 10)).toBeNull();
  });

  it("returns null for empty text", () => {
    expect(detectInlineSlash("", 0)).toBeNull();
  });

  it("returns null when cursor is at 0", () => {
    expect(detectInlineSlash("/foo", 0)).toBeNull();
  });

  it("detects slug with hyphens", () => {
    expect(detectInlineSlash("run /my-cool-skill", 18)).toEqual({
      token: "/my-cool-skill",
      start: 4,
      end: 18,
    });
  });

  it("returns null when cursor is in the middle of regular text", () => {
    expect(detectInlineSlash("no slash here", 5)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// filterInlineSuggestions
// ---------------------------------------------------------------------------

describe("filterInlineSuggestions", () => {
  it("returns all options for just /", () => {
    const result = filterInlineSuggestions("/", options, 10);
    expect(result.length).toBe(options.length);
  });

  it("filters by prefix", () => {
    const result = filterInlineSuggestions("/s", options, 10);
    expect(result.every((o) => o.value.startsWith("/s"))).toBe(true);
    expect(result.length).toBe(3); // /scan, /session, /settings
  });

  it("returns empty for exact match (already completed)", () => {
    expect(filterInlineSuggestions("/scan", options, 10)).toEqual([]);
  });

  it("returns empty for no match", () => {
    expect(filterInlineSuggestions("/zzz", options, 10)).toEqual([]);
  });

  it("respects maxSuggestions", () => {
    expect(filterInlineSuggestions("/", options, 2).length).toBe(2);
  });

  it("returns empty for non-slash token", () => {
    expect(filterInlineSuggestions("scan", options, 10)).toEqual([]);
  });

  it("returns empty for empty options", () => {
    expect(filterInlineSuggestions("/s", [], 10)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// computeInlineCompletion
// ---------------------------------------------------------------------------

describe("computeInlineCompletion", () => {
  it("replaces inline partial with completed value", () => {
    const result = computeInlineCompletion(
      "scan this /v",
      { token: "/v", start: 10, end: 12 },
      "/vulnerability-analysis",
    );
    expect(result.newText).toBe("scan this /vulnerability-analysis");
    expect(result.cursorOffset).toBe(33);
  });

  it("replaces start-of-line partial", () => {
    const result = computeInlineCompletion(
      "/sc",
      { token: "/sc", start: 0, end: 3 },
      "/scan",
    );
    expect(result.newText).toBe("/scan");
    expect(result.cursorOffset).toBe(5);
  });

  it("preserves text after the token", () => {
    const result = computeInlineCompletion(
      "run /s more text",
      { token: "/s", start: 4, end: 6 },
      "/scan",
    );
    expect(result.newText).toBe("run /scan more text");
    expect(result.cursorOffset).toBe(9);
  });

  it("handles token at end of text", () => {
    const result = computeInlineCompletion(
      "test /h",
      { token: "/h", start: 5, end: 7 },
      "/help",
    );
    expect(result.newText).toBe("test /help");
    expect(result.cursorOffset).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// detectInlineOption
// ---------------------------------------------------------------------------

const knownCommands = new Set(["pentest", "p", "operator", "o", "themes"]);

describe("detectInlineOption", () => {
  it("detects -- after a known command", () => {
    expect(detectInlineOption("/pentest --", 11, knownCommands)).toEqual({
      commandName: "pentest",
      token: "--",
      start: 9,
      end: 11,
    });
  });

  it("detects partial option", () => {
    expect(detectInlineOption("/pentest --tar", 14, knownCommands)).toEqual({
      commandName: "pentest",
      token: "--tar",
      start: 9,
      end: 14,
    });
  });

  it("detects option after existing flags", () => {
    const text = "/pentest --target http://foo --na";
    expect(detectInlineOption(text, text.length, knownCommands)).toEqual({
      commandName: "pentest",
      token: "--na",
      start: 29,
      end: 33,
    });
  });

  it("works with aliases", () => {
    expect(detectInlineOption("/p --target", 11, knownCommands)).toEqual({
      commandName: "p",
      token: "--target",
      start: 3,
      end: 11,
    });
  });

  it("returns null for unknown command", () => {
    expect(detectInlineOption("/unknown --tar", 14, knownCommands)).toBeNull();
  });

  it("returns null when no command prefix", () => {
    expect(detectInlineOption("hello --tar", 11, knownCommands)).toBeNull();
  });

  it("returns null when -- is not preceded by whitespace", () => {
    expect(detectInlineOption("/pentest x--tar", 15, knownCommands)).toBeNull();
  });

  it("returns null when cursor is at 0", () => {
    expect(detectInlineOption("--target", 0, knownCommands)).toBeNull();
  });

  it("returns null for single dash", () => {
    expect(detectInlineOption("/pentest -t", 11, knownCommands)).toBeNull();
  });

  it("returns null with empty known commands", () => {
    expect(detectInlineOption("/pentest --tar", 14, new Set())).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// filterInlineOptionSuggestions
// ---------------------------------------------------------------------------

const optionSuggestions: AutocompleteOption[] = [
  { value: "--target", label: "--target <url>", description: "Target URL" },
  { value: "--name", label: "--name <name>", description: "Session name" },
  { value: "--tier", label: "--tier <1-5>", description: "Permission tier" },
  { value: "--strict", label: "--strict", description: "Strict scope mode" },
];

describe("filterInlineOptionSuggestions", () => {
  it("returns all options for just --", () => {
    const result = filterInlineOptionSuggestions(
      "--",
      optionSuggestions,
      "/pentest --",
      10,
    );
    expect(result.length).toBe(optionSuggestions.length);
  });

  it("filters by prefix", () => {
    const result = filterInlineOptionSuggestions(
      "--t",
      optionSuggestions,
      "/pentest --t",
      10,
    );
    expect(result.every((o) => o.value.startsWith("--t"))).toBe(true);
    expect(result.length).toBe(2); // --target, --tier
  });

  it("returns empty for exact match", () => {
    expect(
      filterInlineOptionSuggestions(
        "--target",
        optionSuggestions,
        "/pentest --target",
        10,
      ),
    ).toEqual([]);
  });

  it("excludes already-used options from results", () => {
    const fullText = "/pentest --target http://foo --";
    const result = filterInlineOptionSuggestions(
      "--",
      optionSuggestions,
      fullText,
      10,
    );
    expect(result.some((o) => o.value === "--target")).toBe(false);
    expect(result.length).toBe(3); // --name, --tier, --strict
  });

  it("respects maxSuggestions", () => {
    expect(
      filterInlineOptionSuggestions("--", optionSuggestions, "/pentest --", 2)
        .length,
    ).toBe(2);
  });

  it("returns empty for non-dash token", () => {
    expect(
      filterInlineOptionSuggestions(
        "target",
        optionSuggestions,
        "/pentest target",
        10,
      ),
    ).toEqual([]);
  });

  it("returns empty for empty options", () => {
    expect(
      filterInlineOptionSuggestions("--t", [], "/pentest --t", 10),
    ).toEqual([]);
  });

  it("is case-insensitive", () => {
    const result = filterInlineOptionSuggestions(
      "--T",
      optionSuggestions,
      "/pentest --T",
      10,
    );
    expect(result.length).toBe(2); // --target, --tier
  });
});
