import { useState, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import Input from "./input";
import type { InputProps } from "@opentui/react";

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

export default function Autocomplete({
  label,
  value,
  placeholder,
  focused,
  options,
  onSubmit,
  onInput,
  maxSuggestions = 5,
  ...inputProps
}: AutocompleteProps) {
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [showSuggestions, setShowSuggestions] = useState(false);

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
  });

  const handleSubmit = (val: string) => {
    // If a suggestion is selected, use it
    if (selectedIndex >= 0 && selectedIndex < suggestions.length) {
      const selected = suggestions[selectedIndex];
      if (selected && onSubmit) {
        onSubmit(selected.value);
      }
    } else {
      // Otherwise use the typed value
      if (onSubmit) {
        onSubmit(val);
      }
    }
    setSelectedIndex(-1);
    setShowSuggestions(false);
  };

  return (
    <box flexDirection="column" width="100%">
      <Input
        label={label}
        value={value}
        placeholder={placeholder}
        focused={focused}
        onInput={onInput}
        onSubmit={handleSubmit}
        {...inputProps}
      />

      {showSuggestions && suggestions.length > 0 && (
        <box
          border={true}
          borderColor="green"
          backgroundColor="black"
          width="100%"
          flexDirection="column"
        >
          {suggestions.map((suggestion, index) => (
            <box
              key={suggestion.value}
              backgroundColor={
                index === selectedIndex ? "#1a1a1a" : "transparent"
              }
              flexDirection="row"
              gap={1}
            >
              <text fg={index === selectedIndex ? "green" : "white"}>
                {index === selectedIndex ? "▶" : " "}
              </text>
              <text fg={index === selectedIndex ? "green" : "white"}>
                {suggestion.label}
              </text>
              {suggestion.description ? (
                <text fg="gray"> - {suggestion.description}</text>
              ) : null}
            </box>
          ))}
        </box>
      )}
    </box>
  );
}
