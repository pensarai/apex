import {
  useState,
  useEffect,
  useImperativeHandle,
  forwardRef,
  useRef,
  useMemo,
} from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import {
  SyntaxStyle,
  type TextareaRenderable,
  type RGBA,
  type KeyBinding as TextareaKeyBinding,
} from "@opentui/core";
import { useTheme } from "../../theme";
import { useInput } from "../../context/input";
import { useFocus } from "../../context/focus";
import {
  filterInlineSuggestions,
  detectInlineSlash,
  computeInlineCompletion,
  resolveSubmitValue,
  computeUpArrow,
  computeDownArrow,
  computeTab,
  shouldResetHistory,
  computeVisibleWindow,
  type InlineSlashContext,
} from "./prompt-input-logic";
import { usePasteExtmarks } from "./use-paste-extmarks";
export interface AutocompleteOption {
  value: string;
  label: string;
  description?: string;
}

/**
 * Chat-style keybindings: Enter submits, Shift+Enter / Ctrl+J inserts newline.
 * Overrides @opentui defaults (return=newline, Cmd+return=submit).
 *
 * Both "return" (\r) and "linefeed" (\n) need shift variants because
 * @opentui matches modifiers exactly (Kitty protocol reports shift explicitly).
 */
const chatKeyBindings: TextareaKeyBinding[] = [
  { name: "return", action: "submit" },
  { name: "linefeed", action: "newline" },
  { name: "return", shift: true, action: "newline" },
  { name: "linefeed", shift: true, action: "newline" },
];

// Highlight ref ID for slash command highlighting (stable across renders)
const SLASH_HL_REF = 99;

// Regex for finding /slug patterns in text (reused per content change)
const SLASH_PATTERN = /(?:^|(?<=\s))\/[a-zA-Z0-9][-a-zA-Z0-9]*/gm;

export interface PromptInputRef {
  focus: () => void;
  blur: () => void;
  reset: () => void;
  setValue: (value: string) => void;
  getValue: () => string;
  getTextareaRef: () => TextareaRenderable | null;
}

interface PromptInputProps {
  // Appearance props
  width?: number | "auto" | `${number}%`;
  minHeight?: number;
  maxHeight?: number;
  focused?: boolean;
  placeholder?: string;
  textColor?: string | RGBA;
  focusedTextColor?: string | RGBA;
  backgroundColor?: string;
  focusedBackgroundColor?: string;
  cursorColor?: string;

  // Callbacks
  onSubmit?: (value: string) => void;

  // Autocomplete configuration
  enableAutocomplete?: boolean;
  autocompleteOptions?: AutocompleteOption[];
  maxSuggestions?: number;
  maxVisibleSuggestions?: number;

  // Command execution
  enableCommands?: boolean;
  onCommandExecute?: (command: string) => Promise<void>;

  // Command history (up/down arrow navigation)
  commandHistory?: string[];

  // When true, Up/Down history navigation is suppressed (e.g. queue navigation takes priority)
  disableHistoryNavigation?: boolean;

  // Visual customization
  showPromptIndicator?: boolean;

  // Whether autocomplete suggestions appear above or below the input
  autocompletePlacement?: "above" | "below";

  // Slash command highlighting — colors /slug patterns in the input
  highlightSlashCommands?: boolean;
}

export const PromptInput = forwardRef<PromptInputRef, PromptInputProps>(
  function PromptInput(
    {
      width,
      minHeight = 1,
      maxHeight = 6,
      focused = true,
      placeholder,
      textColor,
      focusedTextColor,
      backgroundColor,
      focusedBackgroundColor,
      cursorColor,
      onSubmit,
      enableAutocomplete = false,
      autocompleteOptions = [],
      maxSuggestions = 10,
      maxVisibleSuggestions = 6,
      enableCommands = false,
      onCommandExecute,
      commandHistory = [],
      disableHistoryNavigation = false,
      showPromptIndicator = false,
      autocompletePlacement = "below",
      highlightSlashCommands = false,
    },
    ref,
  ) {
    const { colors } = useTheme();
    const { inputValue, setInputValue } = useInput();
    const { registerPromptRef } = useFocus();
    const { width: termWidth } = useTerminalDimensions();
    const textareaRef = useRef<TextareaRenderable | null>(null);
    const [selectedSuggestionIndex, setSelectedSuggestionIndex] = useState(-1);

    // Command history navigation state
    // -1 = not browsing history (showing current input)
    const [historyIndex, setHistoryIndex] = useState(-1);
    const savedInputRef = useRef("");
    const historyRef = useRef(commandHistory);
    historyRef.current = commandHistory;
    // Guard to prevent handleContentChange from resetting historyIndex during programmatic setText
    const isNavigatingHistoryRef = useRef(false);

    // Refs to avoid stale closures in handleSubmit (textarea caches onSubmit)
    const selectedIndexRef = useRef(selectedSuggestionIndex);
    const suggestionsRef = useRef<AutocompleteOption[]>([]);
    const onCommandExecuteRef = useRef(onCommandExecute);
    onCommandExecuteRef.current = onCommandExecute;
    const onSubmitRef = useRef(onSubmit);
    onSubmitRef.current = onSubmit;

    const { handlePaste, resolveText, clearPaste } =
      usePasteExtmarks(textareaRef);

    // Inline slash detection state — drives autocomplete filtering
    const [inlineSlashToken, setInlineSlashToken] = useState<string | null>(
      null,
    );
    const inlineSlashContextRef = useRef<InlineSlashContext | null>(null);

    const suggestions = useMemo(() => {
      if (!enableAutocomplete) return [];
      // Inline slash detection drives suggestions for both start-of-line
      // and mid-text /tokens
      if (inlineSlashToken) {
        return filterInlineSuggestions(
          inlineSlashToken,
          autocompleteOptions,
          maxSuggestions,
        );
      }
      return [];
    }, [
      enableAutocomplete,
      autocompleteOptions,
      inlineSlashToken,
      maxSuggestions,
    ]);

    // Keep refs in sync
    useEffect(() => {
      suggestionsRef.current = suggestions;
    }, [suggestions]);

    useEffect(() => {
      selectedIndexRef.current = selectedSuggestionIndex;
    }, [selectedSuggestionIndex]);

    // Reset selection when suggestions change
    useEffect(() => {
      setSelectedSuggestionIndex(suggestions.length > 0 ? 0 : -1);
    }, [suggestions.length]);

    // Create imperative handle
    const imperativeRef = useRef<PromptInputRef>({
      focus: () => textareaRef.current?.focus(),
      blur: () => textareaRef.current?.blur(),
      reset: () => {
        setInputValue("");
        textareaRef.current?.setText("");
        clearPaste();
        setSelectedSuggestionIndex(-1);
      },
      setValue: (value: string) => {
        setInputValue(value);
        textareaRef.current?.setText(value);
        clearPaste();
      },
      getValue: () => inputValue,
      getTextareaRef: () => textareaRef.current,
    });

    // Update the imperative ref when inputValue changes
    useEffect(() => {
      imperativeRef.current.getValue = () => inputValue;
    }, [inputValue]);

    // Expose methods via ref
    useImperativeHandle(ref, () => imperativeRef.current, []);

    // Register with focus context on mount
    useEffect(() => {
      registerPromptRef(imperativeRef.current);
      return () => registerPromptRef(null);
    }, [registerPromptRef]);

    // Slash command highlighting — creates a SyntaxStyle and applies
    // character-range highlights for known /slug patterns in the input text.
    const slashStyleRef = useRef<{
      style: SyntaxStyle;
      styleId: number;
    } | null>(null);

    // Build set of known slugs from autocomplete options for highlight matching
    const knownSlugs = useMemo(() => {
      const slugs = new Set<string>();
      if (highlightSlashCommands) {
        for (const opt of autocompleteOptions) {
          if (opt.value.startsWith("/")) slugs.add(opt.value.toLowerCase());
        }
      }
      return slugs;
    }, [highlightSlashCommands, autocompleteOptions]);

    useEffect(() => {
      if (!highlightSlashCommands) return;
      const style = SyntaxStyle.create();
      const styleId = style.registerStyle("slash-cmd", {
        fg: colors.secondary,
      });
      slashStyleRef.current = { style, styleId };
      if (textareaRef.current) {
        textareaRef.current.syntaxStyle = style;
      }
      return () => {
        slashStyleRef.current = null;
        style.destroy();
      };
    }, [highlightSlashCommands, colors.secondary]);

    const applySlashHighlights = (text: string) => {
      const ta = textareaRef.current;
      const styleCtx = slashStyleRef.current;
      if (!ta || !styleCtx) return;
      ta.removeHighlightsByRef(SLASH_HL_REF);
      if (knownSlugs.size === 0) return;
      SLASH_PATTERN.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = SLASH_PATTERN.exec(text)) !== null) {
        if (knownSlugs.has(match[0].toLowerCase())) {
          ta.addHighlightByCharRange({
            start: match.index,
            end: match.index + match[0].length,
            styleId: styleCtx.styleId,
            hlRef: SLASH_HL_REF,
          });
        }
      }
    };

    // Handle keyboard navigation for suggestions and command history.
    //
    // Priority: up/down navigate command history. When the user reaches
    // the bottom of history (current input) and presses down again with
    // autocomplete suggestions visible, navigation overflows into the
    // suggestion list. Pressing up past the top of the list exits back
    // to history. Tab always accepts the highlighted suggestion.
    useKeyboard((key) => {
      if (!focused) return;

      // --- Ctrl+C: clear input ------------------------------------------
      if (key.ctrl && key.name === "c") {
        textareaRef.current?.setText("");
        clearPaste();
        setInputValue("");
        setHistoryIndex(-1);
        setSelectedSuggestionIndex(-1);
        return;
      }

      // --- Tab: accept the highlighted autocomplete suggestion -----------
      if (suggestions.length > 0 && key.name === "tab") {
        key.preventDefault?.();
        const tabResult = computeTab(suggestions, selectedIndexRef.current);
        if (tabResult) {
          setSelectedSuggestionIndex(tabResult.selectedSuggestionIndex);
          if (tabResult.acceptedValue !== null) {
            clearPaste();
            const slashCtx = inlineSlashContextRef.current;
            if (slashCtx) {
              const text = textareaRef.current?.plainText ?? "";
              const { newText, cursorOffset } = computeInlineCompletion(
                text,
                slashCtx,
                tabResult.acceptedValue,
              );
              textareaRef.current?.setText(newText);
              setInputValue(newText);
              const ta = textareaRef.current;
              setTimeout(() => {
                if (ta) ta.cursorOffset = cursorOffset;
              }, 0);
            } else {
              textareaRef.current?.setText(tabResult.acceptedValue);
              setInputValue(tabResult.acceptedValue);
              textareaRef.current?.gotoLineEnd();
            }
          }
        }
        return;
      }

      // Skip history navigation when parent handles Up/Down (e.g. queue navigation)
      if (disableHistoryNavigation) return;

      const history = historyRef.current;
      const currentState = {
        historyIndex,
        selectedSuggestionIndex: selectedIndexRef.current,
      };

      // --- Up arrow -----------------------------------------------------
      if (key.name === "up") {
        const result = computeUpArrow(
          currentState,
          history,
          suggestions.length,
        );
        if (!result) return;

        if (result.saveCurrentInput) {
          savedInputRef.current = resolveText(
            textareaRef.current?.plainText ?? "",
          );
        }
        setSelectedSuggestionIndex(result.nextState.selectedSuggestionIndex);
        if (result.textToSet !== null) {
          isNavigatingHistoryRef.current = true;
          clearPaste();
          textareaRef.current?.setText(result.textToSet);
          setInputValue(result.textToSet);
          setHistoryIndex(result.nextState.historyIndex);
          setTimeout(() => {
            isNavigatingHistoryRef.current = false;
            textareaRef.current?.gotoLineEnd();
          }, 0);
        } else {
          setHistoryIndex(result.nextState.historyIndex);
        }
        return;
      }

      // --- Down arrow ---------------------------------------------------
      if (key.name === "down") {
        const result = computeDownArrow(
          currentState,
          history,
          suggestions.length,
          savedInputRef.current,
        );
        if (!result) return;

        setSelectedSuggestionIndex(result.nextState.selectedSuggestionIndex);
        if (result.textToSet !== null) {
          isNavigatingHistoryRef.current = true;
          clearPaste();
          textareaRef.current?.setText(result.textToSet);
          setInputValue(result.textToSet);
          setHistoryIndex(result.nextState.historyIndex);
          setTimeout(() => {
            isNavigatingHistoryRef.current = false;
            textareaRef.current?.gotoLineEnd();
          }, 0);
        } else {
          setHistoryIndex(result.nextState.historyIndex);
        }
        return;
      }
    });

    // Submit handler called by textarea's onSubmit.
    // Uses refs for all callbacks because textarea caches onSubmit at mount.
    const handleSubmit = async () => {
      const currentSuggestions = suggestionsRef.current;
      const currentSelectedIndex = selectedIndexRef.current;
      // Resolve paste placeholders to full text before submit
      const rawText = resolveText(textareaRef.current?.plainText ?? "");

      // For inline slash (mid-text), Enter submits raw text — Tab is for
      // completion. For start-of-line commands, keep the current behavior
      // where Enter accepts the selected suggestion.
      const isInlineSlash =
        inlineSlashContextRef.current != null &&
        inlineSlashContextRef.current.start > 0;

      const valueToSubmit = isInlineSlash
        ? rawText.trim()
        : resolveSubmitValue(rawText, currentSuggestions, currentSelectedIndex);

      if (currentSuggestions.length > 0 && currentSelectedIndex >= 0) {
        setSelectedSuggestionIndex(-1);
      }

      if (!valueToSubmit) return;

      if (enableCommands && valueToSubmit.startsWith("/")) {
        await onCommandExecuteRef.current?.(valueToSubmit);
        setInputValue("");
        textareaRef.current?.setText("");
        clearPaste();
        setSelectedSuggestionIndex(-1);
        setHistoryIndex(-1);
        return;
      }

      setHistoryIndex(-1);
      clearPaste();
      onSubmitRef.current?.(valueToSubmit);
    };

    // Content change syncs to context and resets history browsing
    const handleContentChange = () => {
      const text = textareaRef.current?.plainText ?? "";
      const cursorOffset = textareaRef.current?.cursorOffset ?? text.length;
      setInputValue(text);

      // Detect inline /token at cursor for autocomplete
      const slashCtx = detectInlineSlash(text, cursorOffset);
      inlineSlashContextRef.current = slashCtx;
      setInlineSlashToken(slashCtx?.token ?? null);

      applySlashHighlights(text);

      if (shouldResetHistory(historyIndex, isNavigatingHistoryRef.current)) {
        setHistoryIndex(-1);
      }
    };

    // Compute windowed view of suggestions
    const windowedView = useMemo(
      () =>
        computeVisibleWindow(
          suggestions,
          selectedSuggestionIndex,
          maxVisibleSuggestions,
        ),
      [suggestions, selectedSuggestionIndex, maxVisibleSuggestions],
    );

    // Fixed-width label column for grid-like alignment
    const maxLabelWidth = useMemo(
      () => suggestions.reduce((max, s) => Math.max(max, s.label.length), 0),
      [suggestions],
    );

    // Available width for description: total - indicator(3) - label - space(1)
    const descriptionWidth = Math.max(10, termWidth - 3 - maxLabelWidth - 1);

    const suggestionsBox = suggestions.length > 0 && (
      <box
        flexDirection="column"
        {...(autocompletePlacement === "above"
          ? { marginBottom: 1 }
          : { marginTop: 1 })}
      >
        {/* Scroll indicator for more suggestions above */}
        {windowedView.hasMore && (
          <box flexDirection="row" gap={1}>
            <text fg={colors.textMuted}> ↑</text>
            <text fg={colors.textMuted}>
              {windowedView.start} more above...
            </text>
          </box>
        )}

        {/* Visible suggestions window */}
        {windowedView.visibleSuggestions.map((suggestion, windowIndex) => {
          const actualIndex = windowedView.start + windowIndex;
          const isSelected = actualIndex === selectedSuggestionIndex;
          const paddedLabel = suggestion.label.padEnd(maxLabelWidth);
          const desc = suggestion.description
            ? suggestion.description.length > descriptionWidth
              ? suggestion.description.slice(0, descriptionWidth - 1) + "\u2026"
              : suggestion.description
            : "";
          return (
            <box key={suggestion.value}>
              <text>
                <span fg={isSelected ? colors.primary : colors.textMuted}>
                  {isSelected ? " \u25B8 " : "   "}
                </span>
                <span fg={isSelected ? colors.text : colors.textMuted}>
                  {paddedLabel}
                </span>
                {desc && (
                  <span fg={colors.textMuted}> {desc}</span>
                )}
              </text>
            </box>
          );
        })}

        {/* Scroll indicator for more suggestions below */}
        {windowedView.hasMoreBelow && (
          <box flexDirection="row" gap={1}>
            <text fg={colors.textMuted}> ↓</text>
            <text fg={colors.textMuted}>
              {suggestions.length - windowedView.end} more below...
            </text>
          </box>
        )}
      </box>
    );

    return (
      <box flexDirection="column">
        {autocompletePlacement === "above" && suggestionsBox}

        {/* Input row with optional prompt indicator */}
        <box flexDirection="row">
          {showPromptIndicator && (
            <text marginRight={2} fg={colors.primary}>
              {"❯ "}
            </text>
          )}
          <textarea
            ref={textareaRef}
            width={width}
            minHeight={minHeight}
            maxHeight={maxHeight}
            focused={focused}
            placeholder={placeholder}
            textColor={textColor}
            focusedTextColor={focusedTextColor}
            backgroundColor={backgroundColor}
            focusedBackgroundColor={focusedBackgroundColor}
            cursorColor={cursorColor ?? colors.textMuted}
            keyBindings={chatKeyBindings}
            onContentChange={handleContentChange}
            onSubmit={handleSubmit}
            onPaste={handlePaste}
          />
        </box>

        {autocompletePlacement === "below" && suggestionsBox}
      </box>
    );
  },
);

export default PromptInput;
