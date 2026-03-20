/**
 * Help Dialog Component
 *
 * Modal overlay for viewing available commands.
 * Shows commands in a scrollable list with detail view for options/flags.
 */

import { useState, useEffect, useRef, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { ScrollBoxRenderable } from "@opentui/core";
import { scrollToIndex } from "../../utils/scroll";
import { useCommand } from "../../context/command";
import { Dialog } from "../../context/dialog";
import type { CommandConfig } from "../../command-registry";
import { useTheme } from "../../theme";

interface HelpDialogProps {
  onClose: () => void;
}

export default function HelpDialog({ onClose }: HelpDialogProps) {
  const { colors } = useTheme();
  const { commands } = useCommand();

  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showDetail, setShowDetail] = useState(false);
  const scrollboxRef = useRef<ScrollBoxRenderable | null>(null);

  // Group commands by category
  const commandsByCategory = useMemo(() => {
    const grouped: Record<string, CommandConfig[]> = {};
    for (const cmd of commands) {
      const category = cmd.category || "Other";
      if (!grouped[category]) {
        grouped[category] = [];
      }
      grouped[category].push(cmd);
    }
    return grouped;
  }, [commands]);

  // Flat list of commands for navigation - filtered and sorted
  const flatCommands = useMemo(() => {
    // Filter out hidden commands
    const visible = commands.filter((cmd) => !cmd.hidden);

    // Priority order for important commands
    const priorityOrder = [
      "pentest",
      "operator",
      "auth",
      "credits",
      "models",
      "providers",
      "sessions",
    ];

    // Sort with priority commands first, then alphabetically
    return visible.sort((a, b) => {
      const aIndex = priorityOrder.indexOf(a.name);
      const bIndex = priorityOrder.indexOf(b.name);

      // Both in priority list - sort by priority order
      if (aIndex !== -1 && bIndex !== -1) {
        return aIndex - bIndex;
      }

      // Only a is in priority list - a comes first
      if (aIndex !== -1) return -1;

      // Only b is in priority list - b comes first
      if (bIndex !== -1) return 1;

      // Neither in priority list - sort alphabetically
      return a.name.localeCompare(b.name);
    });
  }, [commands]);

  useEffect(() => {
    if (selectedIndex >= flatCommands.length) {
      setSelectedIndex(Math.max(0, flatCommands.length - 1));
    }
  }, [flatCommands.length, selectedIndex]);

  useEffect(() => {
    scrollToIndex(
      scrollboxRef.current,
      selectedIndex,
      flatCommands,
      (cmd) => cmd.name,
    );
  }, [selectedIndex, flatCommands]);

  useKeyboard((evt) => {
    if (evt.name === "escape") {
      evt.preventDefault();
      if (showDetail) {
        setShowDetail(false);
      } else {
        onClose();
      }
      return;
    }

    if (showDetail) {
      if (evt.name === "return") {
        evt.preventDefault();
        setShowDetail(false);
      }
      return;
    }

    switch (evt.name) {
      case "up":
      case "k":
        evt.preventDefault();
        setSelectedIndex((prev) =>
          prev > 0 ? prev - 1 : flatCommands.length - 1,
        );
        break;
      case "down":
      case "j":
        evt.preventDefault();
        setSelectedIndex((prev) =>
          prev < flatCommands.length - 1 ? prev + 1 : 0,
        );
        break;
      case "return":
      case "v":
        evt.preventDefault();
        if (flatCommands[selectedIndex]) {
          setShowDetail(true);
        }
        break;
    }
  });

  const selectedCommand = flatCommands[selectedIndex];

  // Detail view
  if (showDetail && selectedCommand) {
    const hasOptions =
      selectedCommand.options && selectedCommand.options.length > 0;

    return (
      <Dialog size="large" onClose={onClose}>
        <box flexDirection="column" padding={2} gap={1} width="100%">
          {/* Header */}
          <box flexDirection="row" justifyContent="space-between" width="100%">
            <text fg={colors.primary}>/{selectedCommand.name}</text>
            <text fg={colors.textMuted}>esc to close</text>
          </box>

          {/* Description */}
          <text fg={colors.text}>
            {selectedCommand.description || "No description available"}
          </text>

          {/* Aliases */}
          {selectedCommand.aliases && selectedCommand.aliases.length > 0 && (
            <box flexDirection="row">
              <text fg={colors.textMuted}>Aliases: </text>
              <text fg={colors.text}>
                {selectedCommand.aliases.map((a) => `/${a}`).join(", ")}
              </text>
            </box>
          )}

          {/* Options */}
          {hasOptions && (
            <box flexDirection="column" gap={0} marginTop={1}>
              <text fg={colors.textMuted}>Options:</text>
              {selectedCommand.options?.map((opt, idx) => (
                <box key={idx} flexDirection="row" paddingLeft={2} gap={1}>
                  <text fg={colors.primary}>{opt.name}</text>
                  {opt.valueHint && (
                    <text fg={colors.textMuted}>{opt.valueHint}</text>
                  )}
                  <text fg={colors.text}>{opt.description}</text>
                </box>
              ))}
            </box>
          )}

          {/* Footer hint */}
          <box marginTop={1}>
            <text fg={colors.textMuted}>[enter/esc] back</text>
          </box>
        </box>
      </Dialog>
    );
  }

  // List view
  return (
    <Dialog size="large" onClose={onClose}>
      <box flexDirection="column" padding={2} gap={1} width="100%">
        {/* Header */}
        <box flexDirection="row" justifyContent="space-between" width="100%">
          <text fg={colors.text}>Commands</text>
          <text fg={colors.textMuted}>esc to close</text>
        </box>

        {/* Commands list */}
        <scrollbox
          ref={scrollboxRef}
          style={{
            rootOptions: { flexGrow: 1, width: "100%" },
            contentOptions: { flexDirection: "column" },
          }}
          stickyScroll={false}
          focused={true}
        >
          {flatCommands.map((cmd, idx) => {
            const isSelected = idx === selectedIndex;
            return (
              <box
                key={cmd.name}
                id={cmd.name}
                width="100%"
                flexDirection="row"
                gap={2}
                backgroundColor={
                  isSelected ? colors.backgroundSelected : undefined
                }
                overflow="hidden"
              >
                <text fg={isSelected ? colors.primary : colors.text} width={18}>
                  /{cmd.name}
                </text>
                <text fg={isSelected ? colors.text : colors.textMuted}>
                  {cmd.description || ""}
                </text>
              </box>
            );
          })}
        </scrollbox>

        {/* Footer */}
        <text fg={colors.textMuted}>
          [↑/↓] navigate [enter] details [esc] close
        </text>
      </box>
    </Dialog>
  );
}
