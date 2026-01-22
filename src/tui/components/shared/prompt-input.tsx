import { useState, useEffect, useImperativeHandle, forwardRef, useRef, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import type { TextareaRenderable } from "@opentui/core";
import { colors } from "../../theme/colors";
import { useInput } from "../../context/input";
import { useFocus } from "../../context/focus";
import type { AutocompleteOption } from "../autocomplete";

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
  textColor?: string;
  focusedTextColor?: string;
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
      maxSuggestions = 6,
      enableCommands = false,
      onCommandExecute,
      showPromptIndicator = false,
    },
    ref
  ) {
    const { inputValue, setInputValue } = useInput();
    const { registerPromptRef } = useFocus();
    const textareaRef = useRef<TextareaRenderable | null>(null);
    const [selectedSuggestionIndex, setSelectedSuggestionIndex] = useState(-1);

    // Refs to avoid stale closures in handleSubmit
    const selectedIndexRef = useRef(selectedSuggestionIndex);
    const suggestionsRef = useRef<AutocompleteOption[]>([]);

    // Filter suggestions using inputValue from context
    const suggestions = useMemo(() => {
      if (!enableAutocomplete || !autocompleteOptions || !inputValue) return [];
      const input = inputValue.toLowerCase().trim();

      if(!(input[0] === "/")) return [];
      
      return autocompleteOptions
        .filter(
          (opt) =>
            opt.value.toLowerCase().includes(input) ||
            opt.label.toLowerCase().includes(input)
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

    // Handle keyboard navigation for suggestions (up/down/tab)
    useKeyboard((key) => {
      if (!focused || suggestions.length === 0) return;

      if (key.name === "up") {
        setSelectedSuggestionIndex((prev) =>
          prev <= 0 ? suggestions.length - 1 : prev - 1
        );
        return;
      }
      if (key.name === "down") {
        setSelectedSuggestionIndex((prev) =>
          prev >= suggestions.length - 1 ? 0 : prev + 1
        );
        return;
      }
      // Tab to fill suggestion without running command
      if (key.name === "tab") {
        key.preventDefault?.();
        const currentSelectedIndex = selectedIndexRef.current;
        if (currentSelectedIndex >= 0 && currentSelectedIndex < suggestions.length) {
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
    });

    // Submit handler called by textarea's onSubmit
    const handleSubmit = async () => {
      // Read from refs to avoid stale closure
      const currentSuggestions = suggestionsRef.current;
      const currentSelectedIndex = selectedIndexRef.current;

      // If a suggestion is selected, use it as the value to submit
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

      // Handle commands
      if (enableCommands && valueToSubmit.startsWith("/")) {
        await onCommandExecute?.(valueToSubmit);
        setInputValue("");
        textareaRef.current?.setText("");
        setSelectedSuggestionIndex(-1);
        return;
      }

      // Regular submit
      onSubmit?.(valueToSubmit);
    };

    // Content change syncs to context
    const handleContentChange = () => {
      const text = textareaRef.current?.plainText ?? "";
      setInputValue(text);
    };

    return (
      <box flexDirection="column">
        {/* Input row with optional prompt indicator */}
        <box flexDirection="row">
          {showPromptIndicator && (
            <text marginRight={2} fg={colors.greenAccent}>
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
            cursorColor={cursorColor}
            // keyBindings={keyBindings}
            keyBindings={
              [
                {
                  action: "submit",
                  name: "return"
                },
                {
                  action: "newline",
                  meta: true,
                  name: "return"
                }
              ]
            }
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
                  <text fg={isSelected ? colors.greenAccent : colors.dimText}>
                    {isSelected ? " ▸" : "  "}
                  </text>
                  <text fg={isSelected ? colors.creamText : colors.dimText}>
                    {suggestion.label}
                  </text>
                  {suggestion.description && (
                    <text fg={colors.dimText}> {suggestion.description}</text>
                  )}
                </box>
              );
            })}
          </box>
        )}
      </box>
    );
  }
);

export default PromptInput;
