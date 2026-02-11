import { useState, useEffect, forwardRef } from "react";
import { useKeyboard } from "@opentui/react";
import Input from "./input";
import type { InputProps } from "@opentui/react";
import { type InputRenderable, type SubmitEvent } from "@opentui/core";
import { useColors } from "../theme";

export interface AutocompleteOption {
  value: string;
  label: string;
  description?: string;
}

export interface AutocompleteProps extends Omit<InputProps, "onSubmit"> {
  label: string;
  options: AutocompleteOption[];
  onSubmit?: (value: string) => void;
  maxSuggestions?: number;
}

const Autocomplete = forwardRef<InputRenderable, AutocompleteProps>(
  function Autocomplete(
    {
      label,
      value,
      placeholder,
      focused,
      options,
      onSubmit,
      onInput,
      maxSuggestions = 5,
      ...inputProps
    },
    ref,
  ) {
    const [selectedIndex, setSelectedIndex] = useState(-1);
    const [showSuggestions, setShowSuggestions] = useState(false);
    const colors = useColors();

    // Filter suggestions based on input value
    const getSuggestions = (): AutocompleteOption[] => {
      if (!value || typeof value !== "string" || value.length === 0) {
        return [];
      }

      const input = value.toLowerCase().trim();

      return options
        .filter((opt) => {
          const optValue = opt.value.toLowerCase();
          const optLabel = opt.label.toLowerCase();
          return optValue.includes(input) || optLabel.includes(input);
        })
        .slice(0, maxSuggestions);
    };

    const suggestions = getSuggestions();

    // Reset selected index when suggestions change
    useEffect(() => {
      if (suggestions.length === 0) {
        setSelectedIndex(-1);
        setShowSuggestions(false);
      } else {
        setShowSuggestions(true);
      }
    }, [suggestions.length]);

    // Handle keyboard navigation
    useKeyboard((key) => {
      if (!focused) return;

      // Only handle arrow keys if we have suggestions
      if (suggestions.length === 0) return;

      if (key.name === "up") {
        setSelectedIndex((prev) => {
          const newIndex = prev <= 0 ? suggestions.length - 1 : prev - 1;
          return newIndex;
        });
        return;
      }

      if (key.name === "down") {
        setSelectedIndex((prev) => {
          const newIndex = prev >= suggestions.length - 1 ? 0 : prev + 1;
          return newIndex;
        });
        return;
      }

      // Tab to fill suggestion without running command
      if (key.name === "tab") {
        key.preventDefault?.();
        if (selectedIndex >= 0 && selectedIndex < suggestions.length) {
          const selected = suggestions[selectedIndex];
          if (selected && onInput) {
            onInput(selected.value);
          }
          setSelectedIndex(-1);
        }
        return;
      }
    });

    const handleSubmit = (_event: SubmitEvent) => {
      // If a suggestion is selected, use it
      if (selectedIndex >= 0 && selectedIndex < suggestions.length) {
        const selected = suggestions[selectedIndex];
        if (selected && onSubmit) {
          onSubmit(selected.value);
        }
      } else {
        // Otherwise use the typed value
        if (onSubmit) {
          const val = typeof value === "string" ? value : "";
          onSubmit(val);
        }
      }
      setSelectedIndex(-1);
      setShowSuggestions(false);
    };

    return (
      <box width="100%" flexDirection="column">
        <Input
          ref={ref}
          label={label}
          value={value}
          placeholder={placeholder}
          focused={focused}
          onInput={onInput}
          onSubmit={handleSubmit}
          onPaste={(event) => {
            if (!onInput) return;
            const current = typeof value === "string" ? value : "";
            const cleaned = String(event.text).replace(/\r?\n/g, " ");
            onInput(current + cleaned);
          }}
          {...inputProps}
        />
        {showSuggestions && suggestions.length > 0 && (
          <box marginTop={1} marginLeft={2} flexDirection="column">
            {suggestions.map((suggestion, index) => {
              const isSelected = index === selectedIndex;

              return (
                <box key={suggestion.value} flexDirection="row" gap={1}>
                  <text fg={isSelected ? colors.greenAccent : colors.dimText}>
                    {isSelected ? "█" : "░"}
                  </text>
                  <text fg={isSelected ? colors.creamText : colors.dimText}>
                    {suggestion.label}
                  </text>
                  {suggestion.description ? (
                    <text fg={colors.dimText}> {suggestion.description}</text>
                  ) : null}
                </box>
              );
            })}
          </box>
        )}
      </box>
    );
  },
);

export default Autocomplete;
