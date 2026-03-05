import {
  useState,
  useEffect,
  useImperativeHandle,
  forwardRef,
  useRef,
  useMemo,
} from "react";
import { useKeyboard } from "@opentui/react";
import type { TextareaRenderable, RGBA } from "@opentui/core";
import { useTheme } from "../../theme";
import { useInput } from "../../context/input";
import { useFocus } from "../../context/focus";
export interface AutocompleteOption {
  value: string;
  label: string;
  description?: string;
}

// Key binding type for textarea actions
type TextareaAction = "submit" | "newline";
interface KeyBinding {
  name: string;
  ctrl?: boolean;
  shift?: boolean;
  meta?: boolean;
  action: TextareaAction;
}

// Configure Enter to submit, Shift+Enter for newline
const keyBindings: KeyBinding[] = [
  { name: "Enter", action: "submit" },
  { name: "Enter", shift: true, action: "newline" },
];

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

  // Command execution
  enableCommands?: boolean;
  onCommandExecute?: (command: string) => Promise<void>;

  // Command history (up/down arrow navigation)
  commandHistory?: string[];

  // Visual customization
  showPromptIndicator?: boolean;
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
      enableCommands = false,
      onCommandExecute,
      commandHistory = [],
      showPromptIndicator = false,
    },
    ref,
  ) {
    const { colors } = useTheme();
    const { inputValue, setInputValue } = useInput();
    const { registerPromptRef } = useFocus();
    const textareaRef = useRef<TextareaRenderable | null>(null);
    const [selectedSuggestionIndex, setSelectedSuggestionIndex] = useState(-1);

    // Command history navigation state
    // -1 = not browsing history (showing current input)
    const [historyIndex, setHistoryIndex] = useState(-1);
    const savedInputRef = useRef("");
    const historyRef = useRef(commandHistory);
    historyRef.current = commandHistory;

    // Refs to avoid stale closures in handleSubmit (textarea caches onSubmit)
    const selectedIndexRef = useRef(selectedSuggestionIndex);
    const suggestionsRef = useRef<AutocompleteOption[]>([]);
    const onCommandExecuteRef = useRef(onCommandExecute);
    onCommandExecuteRef.current = onCommandExecute;
    const onSubmitRef = useRef(onSubmit);
    onSubmitRef.current = onSubmit;

    // Filter suggestions using inputValue from context
    const suggestions = useMemo(() => {
      if (!enableAutocomplete || !autocompleteOptions || !inputValue) return [];
      const input = inputValue.toLowerCase().trim();

      if (!(input[0] === "/")) return [];

      return autocompleteOptions
        .filter(
          (opt) =>
            opt.value.toLowerCase().includes(input) ||
            opt.label.toLowerCase().includes(input),
        )
        .slice(0, maxSuggestions);
    }, [enableAutocomplete, autocompleteOptions, inputValue, maxSuggestions]);

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
        setSelectedSuggestionIndex(-1);
      },
      setValue: (value: string) => {
        setInputValue(value);
        textareaRef.current?.setText(value);
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

    // Handle keyboard navigation for suggestions and command history
    useKeyboard((key) => {
      if (!focused) return;

      // When autocomplete suggestions are visible, up/down navigates them
      if (suggestions.length > 0) {
        if (key.name === "up") {
          setSelectedSuggestionIndex((prev) =>
            prev <= 0 ? suggestions.length - 1 : prev - 1,
          );
          return;
        }
        if (key.name === "down") {
          setSelectedSuggestionIndex((prev) =>
            prev >= suggestions.length - 1 ? 0 : prev + 1,
          );
          return;
        }
        if (key.name === "tab") {
          key.preventDefault?.();
          const currentSelectedIndex = selectedIndexRef.current;
          if (
            currentSelectedIndex >= 0 &&
            currentSelectedIndex < suggestions.length
          ) {
            const selected = suggestions[currentSelectedIndex];
            if (selected) {
              textareaRef.current?.setText(selected.value);
              setInputValue(selected.value);
              setSelectedSuggestionIndex(-1);
              textareaRef.current?.gotoLineEnd();
            }
          }
          return;
        }
        return;
      }

      // No autocomplete visible — up/down navigates command history
      const history = historyRef.current;
      if (history.length === 0) return;

      if (key.name === "up") {
        setHistoryIndex((prev) => {
          if (prev === -1) {
            savedInputRef.current = textareaRef.current?.plainText ?? "";
          }
          const next = Math.min(prev + 1, history.length - 1);
          const entry = history[history.length - 1 - next];
          if (entry !== undefined) {
            textareaRef.current?.setText(entry);
            setInputValue(entry);
            setTimeout(() => textareaRef.current?.gotoLineEnd(), 0);
          }
          return next;
        });
        return;
      }
      if (key.name === "down") {
        setHistoryIndex((prev) => {
          if (prev <= 0) {
            const saved = savedInputRef.current;
            textareaRef.current?.setText(saved);
            setInputValue(saved);
            setTimeout(() => textareaRef.current?.gotoLineEnd(), 0);
            return -1;
          }
          const next = prev - 1;
          const entry = history[history.length - 1 - next];
          if (entry !== undefined) {
            textareaRef.current?.setText(entry);
            setInputValue(entry);
            setTimeout(() => textareaRef.current?.gotoLineEnd(), 0);
          }
          return next;
        });
        return;
      }
    });

    // Submit handler called by textarea's onSubmit.
    // Uses refs for all callbacks because textarea caches onSubmit at mount.
    const handleSubmit = async () => {
      const currentSuggestions = suggestionsRef.current;
      const currentSelectedIndex = selectedIndexRef.current;

      let valueToSubmit: string;
      if (currentSuggestions.length > 0 && currentSelectedIndex >= 0) {
        const selected = currentSuggestions[currentSelectedIndex];
        if (selected) {
          valueToSubmit = selected.value;
          setSelectedSuggestionIndex(-1);
        } else {
          valueToSubmit = (textareaRef.current?.plainText ?? "").trim();
        }
      } else {
        valueToSubmit = (textareaRef.current?.plainText ?? "").trim();
      }

      if (!valueToSubmit) return;

      if (enableCommands && valueToSubmit.startsWith("/")) {
        await onCommandExecuteRef.current?.(valueToSubmit);
        setInputValue("");
        textareaRef.current?.setText("");
        setSelectedSuggestionIndex(-1);
        setHistoryIndex(-1);
        return;
      }

      setHistoryIndex(-1);
      onSubmitRef.current?.(valueToSubmit);
    };

    // Content change syncs to context and resets history browsing
    const handleContentChange = () => {
      const text = textareaRef.current?.plainText ?? "";
      setInputValue(text);
      if (historyIndex !== -1) {
        setHistoryIndex(-1);
      }
    };

    return (
      <box flexDirection="column">
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
            // keyBindings={keyBindings}
            keyBindings={[
              {
                action: "submit",
                name: "return",
              },
              {
                action: "submit",
                name: "linefeed",
              },
              {
                action: "newline",
                shift: true,
                name: "return",
              },
              {
                action: "newline",
                shift: true,
                name: "linefeed",
              },
            ]}
            onContentChange={handleContentChange}
            onSubmit={handleSubmit}
          />
        </box>

        {/* Autocomplete suggestions */}
        {suggestions.length > 0 && (
          <box flexDirection="column" marginTop={1}>
            {suggestions.map((suggestion, index) => {
              const isSelected = index === selectedSuggestionIndex;
              return (
                <box key={suggestion.value} flexDirection="row" gap={1}>
                  <text fg={isSelected ? colors.primary : colors.textMuted}>
                    {isSelected ? " ▸" : "  "}
                  </text>
                  <text fg={isSelected ? colors.text : colors.textMuted}>
                    {suggestion.label}
                  </text>
                  {suggestion.description && (
                    <text fg={colors.textMuted}> {suggestion.description}</text>
                  )}
                </box>
              );
            })}
          </box>
        )}
      </box>
    );
  },
);

export default PromptInput;
