/**
 * Home View
 *
 * Main entry screen with centered command input:
 * - Green ASCII petri animation
 * - Title and description
 * - Centered command input with inline autocomplete
 */

import { useState, useCallback, useEffect, useMemo } from "react";
import { RGBA, type InputRenderable } from "@opentui/core";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { PetriAnimation } from "./components/petri-animation";
import { useCommand } from "../../command-provider";
import { useInput } from "../../context/input";
import { useFocus } from "../../context/focus";
import { useConfig } from "../../context/config";

// Colors
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

type ViewType = "home" | "config" | "chat";

interface HomeViewProps {
  onNavigate: (view: ViewType, options?: { sessionId?: string; isResume?: boolean }) => void;
  onStartSession: (directive: string) => void;
}

export function HomeView({ onNavigate, onStartSession }: HomeViewProps) {
  const dimensions = useTerminalDimensions();
  const config = useConfig();
  const [inputValue, setInputValue] = useState("");
  const [selectedSuggestionIndex, setSelectedSuggestionIndex] = useState(-1);

  // Get autocomplete options and input sync from contexts
  const { executeCommand, autocompleteOptions } = useCommand();
  const { setInputValue: syncInputValue } = useInput();
  const { commandInputRef } = useFocus();

  // Callback ref to register input with focus context
  const inputRefCallback = (node: InputRenderable | null) => {
    if (node) {
      commandInputRef.current = node;
    }
  };

  // Filter suggestions based on input
  const suggestions = useMemo(() => {
    if (!inputValue || inputValue.length === 0) return [];
    const input = inputValue.toLowerCase().trim();
    return autocompleteOptions
      .filter((opt) => {
        const optValue = opt.value.toLowerCase();
        const optLabel = opt.label.toLowerCase();
        return optValue.includes(input) || optLabel.includes(input);
      })
      .slice(0, 6);
  }, [inputValue, autocompleteOptions]);

  // Reset selection when suggestions change
  useEffect(() => {
    setSelectedSuggestionIndex(suggestions.length > 0 ? 0 : -1);
  }, [suggestions.length]);

  // Sync input state with context
  useEffect(() => {
    syncInputValue(inputValue);
  }, [inputValue, syncInputValue]);

  // Handle keyboard for suggestion navigation
  useKeyboard((key) => {
    if (suggestions.length === 0) return;

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
  });

  const handleSubmit = useCallback(async () => {
    // If a suggestion is selected, use it
    let valueToSubmit = inputValue.trim();
    if (selectedSuggestionIndex >= 0 && selectedSuggestionIndex < suggestions.length) {
      valueToSubmit = suggestions[selectedSuggestionIndex].value;
    }

    if (!valueToSubmit) return;

    // If it starts with /, treat as a command and use executeCommand
    if (valueToSubmit.startsWith("/")) {
      await executeCommand(valueToSubmit);
      setInputValue("");
      syncInputValue("");
      setSelectedSuggestionIndex(-1);
      return;
    }

    // Otherwise, start a session with this directive
    onStartSession(valueToSubmit);
    setInputValue("");
    syncInputValue("");
    setSelectedSuggestionIndex(-1);
  }, [inputValue, selectedSuggestionIndex, suggestions, executeCommand, onStartSession, syncInputValue]);

  // Calculate layout dimensions
  const animationHeight = Math.max(6, Math.floor(dimensions.height * 0.2));
  const inputWidth = Math.min(80, dimensions.width - 10);
  const centerLeft = Math.floor((dimensions.width - inputWidth) / 2);
  const inputTop = animationHeight + 8; // Below animation and title

  return (
    <box
      flexDirection="column"
      width="100%"
      height="100%"
      alignItems="center"
    >
      {/* Petri Animation */}
      <box height={animationHeight} width="100%">
        <PetriAnimation height={animationHeight} />
      </box>

      {/* Title - centered */}
      <box flexDirection="column" alignItems="center" marginTop={1}>
        <text fg={creamText}>
          Apex <span fg={dimText}>({config.data.version || "local"})</span>
        </text>
        <text fg={dimText}>Automated offensive security</text>
      </box>

      {/* Centered Input Area */}
      <box
        flexDirection="column"
        width={inputWidth}
        marginTop={8}
        padding={1}
        border={['left', 'right']}
        borderColor={greenAccent}
      >
        {/* Input */}
        <box flexDirection="row">
          <text marginRight={2} fg={greenAccent}>{"❯ "}</text>
          <input
            ref={inputRefCallback}
            width={inputWidth - 4}
            value={inputValue}
            onInput={setInputValue}
            onSubmit={handleSubmit}
            focused={true}
            placeholder="Type a command or message..."
            textColor="white"
            backgroundColor="transparent"
          />
        </box>

        {/* Autocomplete suggestions - inline below input */}
        {suggestions.length > 0 && (
          <box flexDirection="column" marginTop={1}>
            {suggestions.map((suggestion, index) => {
              const isSelected = index === selectedSuggestionIndex;
              return (
                <box key={suggestion.value} flexDirection="row" gap={1}>
                  <text fg={isSelected ? greenAccent : dimText}>
                    {isSelected ? " ▸" : "  "}
                  </text>
                  <text fg={isSelected ? creamText : dimText}>
                    {suggestion.label}
                  </text>
                  {suggestion.description && (
                    <text fg={dimText}> {suggestion.description}</text>
                  )}
                </box>
              );
            })}
          </box>
        )}

        {/* Help text */}
        <box marginTop={suggestions.length > 0 ? 1 : 0}>
          <text fg={dimText}>
            <span>Type </span>
            <span fg={creamText}>/</span>
            <span> for commands</span>
            <span>  •  </span>
            <span fg={creamText}>Ctrl+S</span>
            <span> sessions</span>
          </text>
        </box>
      </box>
    </box>
  );
}

export default HomeView;
