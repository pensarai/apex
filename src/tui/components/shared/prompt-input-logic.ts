import type { AutocompleteOption } from "./prompt-input";

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
// Inline slash detection (for mid-text autocomplete)
// ---------------------------------------------------------------------------

export interface InlineSlashContext {
  /** The partial /token text (e.g. "/v" or "/") */
  token: string;
  /** Character offset where the / starts */
  start: number;
  /** Character offset at the cursor (end of the partial token) */
  end: number;
}

/**
 * Detect a /slug token at the cursor position.
 * Returns null when the cursor is not immediately after a /partial-slug.
 */
export function detectInlineSlash(
  text: string,
  cursorOffset: number,
): InlineSlashContext | null {
  if (cursorOffset <= 0 || cursorOffset > text.length) return null;

  // Walk backwards from cursor through slug chars
  let i = cursorOffset - 1;
  while (i >= 0 && /[a-zA-Z0-9-]/.test(text[i]!)) i--;

  // Must land on a /
  if (i < 0 || text[i] !== "/") return null;

  // The / must be at the start of text or preceded by whitespace
  if (i > 0 && !/\s/.test(text[i - 1]!)) return null;

  return { token: text.slice(i, cursorOffset), start: i, end: cursorOffset };
}

/**
 * Filter autocomplete options against a partial /token.
 * Returns [] for exact matches (already completed — no suggestions needed).
 */
export function filterInlineSuggestions(
  token: string,
  options: AutocompleteOption[],
  maxSuggestions: number,
): AutocompleteOption[] {
  if (!options.length || !token.startsWith("/")) return [];
  const lower = token.toLowerCase();

  // Don't show suggestions when the token exactly matches an option
  if (options.some((opt) => opt.value.toLowerCase() === lower)) return [];

  return options
    .filter((opt) => opt.value.toLowerCase().startsWith(lower))
    .slice(0, maxSuggestions);
}

/**
 * Compute the new text and cursor position after accepting an inline completion.
 */
export function computeInlineCompletion(
  text: string,
  ctx: InlineSlashContext,
  acceptedValue: string,
): { newText: string; cursorOffset: number } {
  const before = text.slice(0, ctx.start);
  const after = text.slice(ctx.end);
  const newText = before + acceptedValue + after;
  return { newText, cursorOffset: before.length + acceptedValue.length };
}

// ---------------------------------------------------------------------------
// Inline option detection (for --flag autocomplete after a /command)
// ---------------------------------------------------------------------------

export interface InlineOptionContext {
  /** The resolved command name (e.g., "pentest") */
  commandName: string;
  /** The partial --token text (e.g., "--tar" or "--") */
  token: string;
  /** Character offset where the "--" starts */
  start: number;
  /** Character offset at the cursor */
  end: number;
}

/**
 * Detect a --flag token at the cursor position, only when the input starts
 * with a known /command. Returns null when no option is being typed.
 */
export function detectInlineOption(
  text: string,
  cursorOffset: number,
  knownCommands: Set<string>,
): InlineOptionContext | null {
  if (cursorOffset <= 0 || cursorOffset > text.length) return null;

  // Walk backwards from cursor through valid option characters (including -)
  let i = cursorOffset - 1;
  while (i >= 0 && /[a-zA-Z0-9-]/.test(text[i]!)) i--;

  // i is now just before the token start. The token must begin with "--"
  const tokenStart = i + 1;
  const token = text.slice(tokenStart, cursorOffset);
  if (!token.startsWith("--")) return null;

  // The "--" must be preceded by whitespace
  if (tokenStart > 0 && !/\s/.test(text[tokenStart - 1]!)) return null;

  // Extract the leading /command from the text
  const cmdMatch = text.match(/^\/([a-zA-Z0-9][-a-zA-Z0-9]*)/);
  if (!cmdMatch) return null;

  const commandName = cmdMatch[1]!;
  if (!knownCommands.has(commandName)) return null;

  return {
    commandName,
    token,
    start: tokenStart,
    end: cursorOffset,
  };
}

/**
 * Filter command option suggestions against a partial --token.
 * Excludes options already present in the full input text.
 */
export function filterInlineOptionSuggestions(
  token: string,
  options: AutocompleteOption[],
  fullText: string,
  maxSuggestions: number,
): AutocompleteOption[] {
  if (!options.length || !token.startsWith("--")) return [];
  const lower = token.toLowerCase();

  // Don't show suggestions for exact matches
  if (options.some((opt) => opt.value.toLowerCase() === lower)) return [];

  // Find all --flags already used in the input
  const usedFlags = new Set<string>();
  const flagPattern = /--[a-zA-Z][-a-zA-Z0-9]*/g;
  for (
    let match = flagPattern.exec(fullText);
    match !== null;
    match = flagPattern.exec(fullText)
  ) {
    usedFlags.add(match[0].toLowerCase());
  }

  return options
    .filter((opt) => {
      const optLower = opt.value.toLowerCase();
      if (usedFlags.has(optLower) && optLower !== lower) return false;
      return optLower.startsWith(lower);
    })
    .slice(0, maxSuggestions);
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
