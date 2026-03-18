import type { AutocompleteOption } from "./prompt-input";

// ---------------------------------------------------------------------------
// Autocomplete filtering
// ---------------------------------------------------------------------------

export function filterSuggestions(
  inputValue: string,
  options: AutocompleteOption[],
  maxSuggestions: number,
): AutocompleteOption[] {
  if (!options.length || !inputValue) return [];
  const input = inputValue.toLowerCase().trim();
  if (!input.startsWith("/")) return [];

  return options
    .filter(
      (opt) =>
        opt.value.toLowerCase().includes(input) ||
        opt.label.toLowerCase().includes(input),
    )
    .slice(0, maxSuggestions);
}

// ---------------------------------------------------------------------------
// Submit value resolution
// ---------------------------------------------------------------------------

export function resolveSubmitValue(
  rawText: string,
  suggestions: AutocompleteOption[],
  selectedIndex: number,
): string {
  if (suggestions.length > 0 && selectedIndex >= 0) {
    const selected = suggestions[selectedIndex];
    if (selected) return selected.value;
  }
  return rawText.trim();
}

// ---------------------------------------------------------------------------
// Keyboard navigation state helpers
//
// Each function returns the next state (or null when the key should be
// ignored).  The caller is responsible for applying side-effects such as
// calling setText / setInputValue.
// ---------------------------------------------------------------------------

export interface NavState {
  historyIndex: number;
  selectedSuggestionIndex: number;
}

export interface UpArrowResult {
  nextState: NavState;
  /** History entry to display, or null when staying in autocomplete */
  textToSet: string | null;
  /** Whether the current input should be saved before navigating */
  saveCurrentInput: boolean;
}

export function computeUpArrow(
  currentState: NavState,
  history: string[],
  suggestionsCount: number,
): UpArrowResult | null {
  const inAutocomplete = currentState.selectedSuggestionIndex >= 0;

  if (inAutocomplete) {
    if (currentState.selectedSuggestionIndex <= 0) {
      return {
        nextState: {
          historyIndex: currentState.historyIndex,
          selectedSuggestionIndex: -1,
        },
        textToSet: null,
        saveCurrentInput: false,
      };
    }
    return {
      nextState: {
        historyIndex: currentState.historyIndex,
        selectedSuggestionIndex: currentState.selectedSuggestionIndex - 1,
      },
      textToSet: null,
      saveCurrentInput: false,
    };
  }

  if (history.length === 0) return null;

  const saveInput = currentState.historyIndex === -1;
  const nextIdx = Math.min(currentState.historyIndex + 1, history.length - 1);
  const entry = history[history.length - 1 - nextIdx];

  return {
    nextState: {
      historyIndex: nextIdx,
      selectedSuggestionIndex: currentState.selectedSuggestionIndex,
    },
    textToSet: entry ?? null,
    saveCurrentInput: saveInput,
  };
}

export interface DownArrowResult {
  nextState: NavState;
  textToSet: string | null;
}

export function computeDownArrow(
  currentState: NavState,
  history: string[],
  suggestionsCount: number,
  savedInput: string,
): DownArrowResult | null {
  const inAutocomplete = currentState.selectedSuggestionIndex >= 0;

  if (inAutocomplete) {
    if (suggestionsCount <= 1) {
      // Single suggestion — exit autocomplete, fall through to history
      return computeDownArrowFromHistory(
        { ...currentState, selectedSuggestionIndex: -1 },
        history,
        suggestionsCount,
        savedInput,
      );
    }
    const nextIdx =
      currentState.selectedSuggestionIndex >= suggestionsCount - 1
        ? suggestionsCount - 1
        : currentState.selectedSuggestionIndex + 1;
    return {
      nextState: {
        historyIndex: currentState.historyIndex,
        selectedSuggestionIndex: nextIdx,
      },
      textToSet: null,
    };
  }

  return computeDownArrowFromHistory(
    currentState,
    history,
    suggestionsCount,
    savedInput,
  );
}

function computeDownArrowFromHistory(
  currentState: NavState,
  history: string[],
  suggestionsCount: number,
  savedInput: string,
): DownArrowResult | null {
  if (history.length === 0) {
    if (suggestionsCount > 1) {
      return {
        nextState: {
          historyIndex: currentState.historyIndex,
          selectedSuggestionIndex: 0,
        },
        textToSet: null,
      };
    }
    return null;
  }

  if (currentState.historyIndex <= 0) {
    const overflowToAutocomplete =
      currentState.historyIndex === -1 && suggestionsCount > 1;
    return {
      nextState: {
        historyIndex: -1,
        selectedSuggestionIndex: overflowToAutocomplete
          ? 0
          : currentState.selectedSuggestionIndex,
      },
      textToSet: savedInput,
    };
  }

  const nextIdx = currentState.historyIndex - 1;
  const entry = history[history.length - 1 - nextIdx];
  return {
    nextState: {
      historyIndex: nextIdx,
      selectedSuggestionIndex: currentState.selectedSuggestionIndex,
    },
    textToSet: entry ?? null,
  };
}

// ---------------------------------------------------------------------------
// Tab handling
// ---------------------------------------------------------------------------

export interface TabResult {
  selectedSuggestionIndex: number;
  acceptedValue: string | null;
}

export function computeTab(
  suggestions: AutocompleteOption[],
  selectedIndex: number,
): TabResult | null {
  if (suggestions.length === 0) return null;

  if (selectedIndex >= 0 && selectedIndex < suggestions.length) {
    const selected = suggestions[selectedIndex];
    if (selected) {
      return { selectedSuggestionIndex: -1, acceptedValue: selected.value };
    }
  }
  return { selectedSuggestionIndex: 0, acceptedValue: null };
}

// ---------------------------------------------------------------------------
// Content change — should we reset history browsing?
// ---------------------------------------------------------------------------

export function shouldResetHistory(
  historyIndex: number,
  isNavigatingHistory: boolean,
): boolean {
  return historyIndex !== -1 && !isNavigatingHistory;
}

// ---------------------------------------------------------------------------
// Windowed suggestions — limit visible suggestions for small terminals
// ---------------------------------------------------------------------------

export interface WindowedSuggestions {
  /** Start index of the visible window in the full suggestions array */
  start: number;
  /** End index (exclusive) of the visible window */
  end: number;
  /** Subset of suggestions to display */
  visibleSuggestions: AutocompleteOption[];
  /** Whether there are more suggestions above the visible window */
  hasMore: boolean;
  /** Whether there are more suggestions below the visible window */
  hasMoreBelow: boolean;
}

/**
 * Compute a windowed view of suggestions centered around the selected index.
 * This prevents visual overflow on small terminals while maintaining the full
 * suggestion list for navigation.
 *
 * @param suggestions Full list of filtered suggestions
 * @param selectedIndex Currently selected suggestion index (-1 if none)
 * @param maxVisible Maximum number of suggestions to show at once
 * @returns Windowed view with start/end indices and visible suggestions
 */
export function computeVisibleWindow(
  suggestions: AutocompleteOption[],
  selectedIndex: number,
  maxVisible: number,
): WindowedSuggestions {
  if (suggestions.length === 0) {
    return {
      start: 0,
      end: 0,
      visibleSuggestions: [],
      hasMore: false,
      hasMoreBelow: false,
    };
  }

  // If we have fewer suggestions than maxVisible, show all
  if (suggestions.length <= maxVisible) {
    return {
      start: 0,
      end: suggestions.length,
      visibleSuggestions: suggestions,
      hasMore: false,
      hasMoreBelow: false,
    };
  }

  // Compute window centered on selected index
  const safeSelectedIndex = Math.max(0, selectedIndex);

  // Try to center the selected item in the window
  let start = Math.max(0, safeSelectedIndex - Math.floor(maxVisible / 2));
  let end = start + maxVisible;

  // Adjust if window extends past the end
  if (end > suggestions.length) {
    end = suggestions.length;
    start = Math.max(0, end - maxVisible);
  }

  return {
    start,
    end,
    visibleSuggestions: suggestions.slice(start, end),
    hasMore: start > 0,
    hasMoreBelow: end < suggestions.length,
  };
}
