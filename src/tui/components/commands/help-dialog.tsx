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
import {
  type CommandCategory,
  type CommandConfig,
  categories,
} from "../../command-registry";
import { Dialog } from "../../context/dialog";
import { DialogControls } from "../shared/dialog-controls";
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

  // Group visible commands by category, preserving array order within each group
  const groupedCommands = useMemo(() => {
    const visible = commands.filter((cmd) => !cmd.hidden);
    const groups: { category: CommandCategory; commands: CommandConfig[] }[] =
      [];
    const byCategory = new Map<CommandCategory, CommandConfig[]>();

    for (const cmd of visible) {
      const cat: CommandCategory = cmd.category || "General";
      if (!byCategory.has(cat)) byCategory.set(cat, []);
      byCategory.get(cat)!.push(cmd);
    }

    for (const cat of categories) {
      const cmds = byCategory.get(cat);
      if (cmds?.length) groups.push({ category: cat, commands: cmds });
    }

    // Any categories not in categories go at the end
    for (const [cat, cmds] of byCategory) {
      if (!categories.includes(cat)) {
        groups.push({ category: cat, commands: cmds });
      }
    }

    return groups;
  }, [commands]);

  // Flat list for keyboard navigation (commands only, no headers)
  const flatCommands = useMemo(
    () => groupedCommands.flatMap((g) => g.commands),
    [groupedCommands],
  );

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
          <box width="100%">
            <text fg={colors.primary}>/{selectedCommand.name}</text>
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
            <DialogControls
              controls={[
                { key: "Enter/Esc", label: "Back", variant: "primary" },
              ]}
            />
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
        <box width="100%">
          <text fg={colors.text}>Commands</text>
        </box>

        {/* Commands list grouped by category */}
        <scrollbox
          ref={scrollboxRef}
          style={{
            rootOptions: { flexGrow: 1, width: "100%" },
            contentOptions: { flexDirection: "column" },
          }}
          stickyScroll={false}
          focused={true}
        >
          {groupedCommands.map((group, groupIdx) => (
            <box key={group.category} flexDirection="column">
              {/* Category header */}
              <box paddingTop={groupIdx > 0 ? 1 : 0}>
                <text fg={colors.textMuted}>{group.category}</text>
              </box>

              {/* Commands in this category */}
              {group.commands.map((cmd) => {
                const flatIdx = flatCommands.indexOf(cmd);
                const isSelected = flatIdx === selectedIndex;
                return (
                  <box
                    key={cmd.name}
                    id={cmd.name}
                    width="100%"
                    flexDirection="row"
                    gap={2}
                    paddingLeft={2}
                    backgroundColor={
                      isSelected ? colors.backgroundSelected : undefined
                    }
                    overflow="hidden"
                  >
                    <text
                      fg={isSelected ? colors.primary : colors.text}
                      width={18}
                    >
                      /{cmd.name}
                    </text>
                    <text fg={isSelected ? colors.text : colors.textMuted}>
                      {cmd.description || ""}
                    </text>
                  </box>
                );
              })}
            </box>
          ))}
        </scrollbox>

        {/* Footer */}
        <DialogControls
          controls={[
            { key: "↑/↓", label: "Navigate" },
            { key: "Enter", label: "Details", variant: "primary" },
            { key: "Esc", label: "Close" },
          ]}
        />
      </box>
    </Dialog>
  );
}
