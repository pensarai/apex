import {
  type RGBA,
  SyntaxStyle,
  type KeyBinding as TextareaKeyBinding,
  type TextareaRenderable,
} from "@opentui/core";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  deobfuscate as engineDeobfuscate,
  obfuscate as engineObfuscate,
  isObfuscationEnabled,
} from "../../../core/obfuscation";
import { useFocus } from "../../context/focus";
import { useInput } from "../../context/input";
import { useObfuscation } from "../../context/obfuscation";
import { useTheme } from "../../theme";
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
  type InlineOptionContext,
  type InlineSlashContext,
  shouldResetHistory,
} from "./prompt-input-logic";
import { usePasteExtmarks } from "./use-paste-extmarks";

/** Word-wrap text and return at most `maxLines` lines, adding ellipsis if truncated. */
function truncateToLines(
  text: string,
  lineWidth: number,
  maxLines: number,
): string {
  if (lineWidth <= 0 || maxLines <= 0) return "";
  const words = text.split(" ");
  const lines: string[] = [];
  let current = "";
  let i = 0;
  let wordSliced = false;

  while (i < words.length && lines.length < maxLines) {
    const word = words[i];
    if (!current) {
      if (word.length > lineWidth) {
        current = word.slice(0, lineWidth);
        wordSliced = true;
      } else {
        current = word;
      }
      i++;
    } else if ((current + " " + word).length <= lineWidth) {
      current += " " + word;
      i++;
    } else {
      lines.push(current);
      current = "";
    }
  }
  if (current && lines.length < maxLines) {
    lines.push(current);
  }

  // Add ellipsis if there's remaining text or a word was sliced to fit
  if (i < words.length || wordSliced) {
    const last = lines[lines.length - 1];
    lines[lines.length - 1] =
      last.length < lineWidth
        ? last + "\u2026"
        : last.slice(0, lineWidth - 1) + "\u2026";
  }

  return lines.join("\n");
}

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

  // Option autocomplete — shows --flag suggestions after a known /command
  commandOptionMap?: Map<string, AutocompleteOption[]>;
  commandNames?: Set<string>;
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
      maxSuggestions = 50,
      maxVisibleSuggestions = 6,
      enableCommands = false,
      onCommandExecute,
      commandHistory = [],
      disableHistoryNavigation = false,
      showPromptIndicator = false,
      autocompletePlacement = "below",
      highlightSlashCommands = false,
      commandOptionMap,
      commandNames,
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

    // Guard for our own obfuscation-driven setText calls so the
    // re-entrant onContentChange doesn't try to obfuscate again.
    const isObfuscatingRef = useRef(false);

    // Subscribe to obfuscation toggles so we can re-process the buffer
    // when the operator flips `/obfuscate` mid-edit.
    const { enabled: obfuscateEnabled } = useObfuscation();
    useEffect(() => {
      const ta = textareaRef.current;
      if (!ta) return;
      // Skip while a large paste is active — its extmark offsets must
      // not shift under us.
      if (ta.extmarks.getAll().length > 0) return;
      const current = ta.plainText;
      if (!current) return;
      // Slash-commands (`/threat-model --output foo/bar`) must reach the
      // command router intact. The path patterns are aggressive enough
      // that they would otherwise rewrite the command itself or its
      // file-path arguments.
      if (current.startsWith("/")) return;
      const next = obfuscateEnabled
        ? engineObfuscate(current, { aliases: false })
        : engineDeobfuscate(current);
      if (next === current) return;
      isObfuscatingRef.current = true;
      ta.setText(next);
      ta.cursorOffset = next.length;
      isObfuscatingRef.current = false;
      setInputValue(next);
      fullTextRef.current = next;
    }, [obfuscateEnabled, setInputValue]);

    // Inline slash detection state — drives autocomplete filtering
    const [inlineSlashToken, setInlineSlashToken] = useState<string | null>(
      null,
    );
    const inlineSlashContextRef = useRef<InlineSlashContext | null>(null);

    // Inline option detection state — drives --flag autocomplete
    const [inlineOptionToken, setInlineOptionToken] = useState<string | null>(
      null,
    );
    const inlineOptionContextRef = useRef<InlineOptionContext | null>(null);
    // Cache full text for option dedup filtering (avoids extra reads in memo)
    const fullTextRef = useRef("");

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
      // Inline option detection for --flags after a /command
      if (
        inlineOptionToken &&
        inlineOptionContextRef.current &&
        commandOptionMap
      ) {
        const cmdOpts = commandOptionMap.get(
          inlineOptionContextRef.current.commandName,
        );
        if (cmdOpts) {
          return filterInlineOptionSuggestions(
            inlineOptionToken,
            cmdOpts,
            fullTextRef.current,
            maxSuggestions,
          );
        }
      }
      return [];
    }, [
      enableAutocomplete,
      autocompleteOptions,
      inlineSlashToken,
      inlineOptionToken,
      commandOptionMap,
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
      for (
        let match = SLASH_PATTERN.exec(text);
        match !== null;
        match = SLASH_PATTERN.exec(text)
      ) {
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

    // Accept the currently selected autocomplete suggestion.
    // Shared by both Tab and Enter key handlers.
    const acceptSelectedSuggestion = (
      currentSuggestions: AutocompleteOption[],
      currentSelectedIndex: number,
    ): boolean => {
      const tabResult = computeTab(currentSuggestions, currentSelectedIndex);
      if (!tabResult) return false;

      setSelectedSuggestionIndex(tabResult.selectedSuggestionIndex);
      if (tabResult.acceptedValue === null) return true;

      clearPaste();
      const slashCtx = inlineSlashContextRef.current;
      const optCtx = inlineOptionContextRef.current;
      const completionCtx =
        slashCtx ??
        (optCtx
          ? { token: optCtx.token, start: optCtx.start, end: optCtx.end }
          : null);
      if (completionCtx) {
        const text = textareaRef.current?.plainText ?? "";
        // Append trailing space after option completions for UX
        const completedValue =
          optCtx && !slashCtx
            ? tabResult.acceptedValue + " "
            : tabResult.acceptedValue;
        const { newText, cursorOffset } = computeInlineCompletion(
          text,
          completionCtx,
          completedValue,
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
      return true;
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
        acceptSelectedSuggestion(suggestions, selectedIndexRef.current);
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

      // When autocomplete suggestions are visible with a selection,
      // Enter accepts the suggestion (same as Tab) instead of submitting.
      if (currentSuggestions.length > 0 && currentSelectedIndex >= 0) {
        if (
          acceptSelectedSuggestion(currentSuggestions, currentSelectedIndex)
        ) {
          return;
        }
      }

      // Resolve paste placeholders → full text, then expand any
      // obfuscation placeholders the user-typed text may contain back to
      // their original values so the agent receives real input.
      const pasteResolved = resolveText(textareaRef.current?.plainText ?? "");
      const rawText = engineDeobfuscate(pasteResolved);
      const valueToSubmit = rawText.trim();

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
      const ta = textareaRef.current;
      let text = ta?.plainText ?? "";
      let cursorOffset = ta?.cursorOffset ?? text.length;

      // Real-time redaction: when obfuscation is on, replace recognised
      // patterns (URLs, hosts, IPs, emails, …) with stable placeholders
      // as the user types. The originals are recovered on submit via
      // `deobfuscate` so the agent still receives real values.
      //
      // Skipped while paste-extmarks are present: the paste mechanism
      // already shows its own atomic placeholder and the offsets that
      // its `resolveText` walks would shift if we mutated the buffer.
      if (
        ta &&
        !isObfuscatingRef.current &&
        isObfuscationEnabled() &&
        ta.extmarks.getAll().length === 0 &&
        !text.startsWith("/")
      ) {
        const redacted = engineObfuscate(text, { aliases: false });
        if (redacted !== text) {
          isObfuscatingRef.current = true;
          ta.setText(redacted);
          // Replacement may shorten the buffer; the user just typed a
          // value at the end of a token, so end-of-text is the natural
          // cursor home.
          ta.cursorOffset = redacted.length;
          isObfuscatingRef.current = false;
          text = redacted;
          cursorOffset = redacted.length;
        }
      }

      setInputValue(text);
      fullTextRef.current = text;

      // Detect inline /token at cursor for autocomplete
      const slashCtx = detectInlineSlash(text, cursorOffset);
      if (slashCtx) {
        inlineSlashContextRef.current = slashCtx;
        inlineOptionContextRef.current = null;
        setInlineSlashToken(slashCtx.token);
        setInlineOptionToken(null);
      } else if (commandNames?.size) {
        // No slash context — try option detection for --flags
        const optCtx = detectInlineOption(text, cursorOffset, commandNames);
        inlineOptionContextRef.current = optCtx;
        inlineSlashContextRef.current = null;
        setInlineSlashToken(null);
        setInlineOptionToken(optCtx?.token ?? null);
      } else {
        inlineSlashContextRef.current = null;
        inlineOptionContextRef.current = null;
        setInlineSlashToken(null);
        setInlineOptionToken(null);
      }

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

    // Use the component's width prop (when numeric) since the suggestions box
    // renders inside a width-constrained parent, not at full terminal width.
    // When width is non-numeric (e.g. "100%"), approximate by subtracting
    // typical parent chrome (padding + indicator + gap ≈ 6 chars).
    const effectiveWidth =
      typeof width === "number" ? width : Math.max(20, termWidth - 6);
    // Description column width: total - indicator(3) - label - gap(1)
    const descColumnWidth = Math.max(
      10,
      effectiveWidth - 3 - maxLabelWidth - 1,
    );

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
          const desc = suggestion.description
            ? truncateToLines(suggestion.description, descColumnWidth, 2)
            : "";
          return (
            <box key={suggestion.value} flexDirection="row" gap={1}>
              <box width={3 + maxLabelWidth} flexShrink={0}>
                <text>
                  <span fg={isSelected ? colors.primary : colors.textMuted}>
                    {isSelected ? " \u25B8 " : "   "}
                  </span>
                  <span fg={isSelected ? colors.text : colors.textMuted}>
                    {suggestion.label}
                  </span>
                </text>
              </box>
              {desc && <text fg={colors.textMuted}>{desc}</text>}
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
