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
