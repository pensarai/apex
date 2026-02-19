import { useState, useEffect, useRef } from "react";
import { useCommand } from "./context/command";
import { useConfig } from "./context/config";
import { useInput } from "./context/input";
import { Session } from "../core/session";
import Autocomplete from "./components/autocomplete";
import os from "os";
import type { InputRenderable } from "@opentui/core";
import { useTheme } from "./theme";

interface CommandInputProps {
  focused?: boolean;
  inputKey?: number;
}

export default function CommandInput({
  focused = true,
  inputKey = 0,
}: CommandInputProps) {
  const [command, setCommand] = useState("");
  const [recentSessions, setRecentSessions] = useState<Session.SessionInfo[]>(
    [],
  );
  const { executeCommand, autocompleteOptions } = useCommand();
  const config = useConfig();
  const { setInputValue } = useInput();
  const autocompleteRef = useRef<InputRenderable | null>(null);

  // Callback ref to register input
  const inputRefCallback = (node: InputRenderable | null) => {
    autocompleteRef.current = node;
  };

  // Load recent sessions
  useEffect(() => {
    const loadRecentSessions = async () => {
      const sessions: Session.SessionInfo[] = [];
      for await (const session of Session.list()) {
        sessions.push(session);
        if (sessions.length >= 3) break; // Only show 3 most recent
      }
      // Sort by updated time (most recent first)
      sessions.sort((a, b) => b.time.updated - a.time.updated);
      setRecentSessions(sessions);
    };
    loadRecentSessions();
  }, []);

  // Sync input state with context
  useEffect(() => {
    setInputValue(command);
  }, [command, setInputValue]);

  // Reset input when inputKey changes
  useEffect(() => {
    setCommand("");
    setInputValue("");
  }, [inputKey, setInputValue]);

  const handleSubmit = async (value: string) => {
    const raw = value ?? "";
    if (raw.trim()) {
      await executeCommand(raw);
      setCommand("");
      setInputValue("");
    }
  };

  const handleInput = (value: string) => {
    setCommand(value);
    setInputValue(value);
  };

  const { colors } = useTheme();

  const cwd = "~" + process.cwd().split(os.homedir()).pop() || "";

  return (
    <box width={"100%"} flexDirection="column" marginTop={1} rowGap={1}>
      {/* Sleek command input bar */}
      <box
        width={"100%"}
        flexDirection="row"
        alignItems="center"
        paddingLeft={1}
        paddingRight={1}
      >
        {/* Prompt indicator */}
        <text fg={colors.primary}>
          <span>{"❯ "}</span>
        </text>

        {/* Input field */}
        <Autocomplete
          ref={inputRefCallback}
          label=""
          options={autocompleteOptions}
          value={command}
          onInput={handleInput}
          onSubmit={handleSubmit}
          focused={focused}
          placeholder="Type a command..."
          maxSuggestions={10}
        />
      </box>

      {/* Subtle hint line */}
      <box paddingLeft={3}>
        <text fg={colors.textMuted}>
          <span>Press </span>
          <span fg={colors.text}>/</span>
          <span> for commands</span>
          <span> • </span>
          <span fg={colors.text}>{`[↓][↑]`}</span>
          <span> navigate</span>
          <span> • </span>
          <span fg={colors.text}>[tab]</span>
          <span> complete</span>
          <span> • </span>
          <span fg={colors.text}>[enter]</span>
          <span> run</span>
        </text>
      </box>
    </box>
  );
}
