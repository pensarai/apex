/**
 * Help Dialog Component
 *
 * Modal overlay for viewing available commands.
 * Shows commands in a scrollable list with detail view for options/flags.
 * Press Enter/v to view detailed description of selected command.
 */

import { useState, useEffect, useRef, useMemo } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { ScrollBoxRenderable } from "@opentui/core";
import { useCommand } from "../../context/command";
import { useRoute } from "../../context/route";
import { useColors } from "../../theme";
import type { CommandConfig } from "../../command-registry";

export default function HelpDialog() {
  const colors = useColors();
  const { commands } = useCommand();
  const route = useRoute();
  const dimensions = useTerminalDimensions();

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

  // Flat list of commands for navigation
  const flatCommands = useMemo(() => {
    return commands;
  }, [commands]);

  // Ensure selected index is within bounds
  useEffect(() => {
    if (selectedIndex >= flatCommands.length) {
      setSelectedIndex(Math.max(0, flatCommands.length - 1));
    }
  }, [flatCommands.length, selectedIndex]);

  // Scroll to keep selected item in view
  useEffect(() => {
    if (!scrollboxRef.current || flatCommands.length === 0) return;

    const scroll = scrollboxRef.current;
    const viewportHeight = scroll.height;
    const children = scroll.getChildren();

    const selectedCmd = flatCommands[selectedIndex];
    if (!selectedCmd) return;

    const target = children.find(child => child.id === selectedCmd.name);
    if (!target) return;

    const targetVisualY = target.y - scroll.y;
    const targetHeight = target.height || 1;

    if (targetVisualY + targetHeight > viewportHeight) {
      scroll.scrollBy(targetVisualY - viewportHeight + targetHeight + 1);
    } else if (targetVisualY < 0) {
      scroll.scrollBy(targetVisualY);
    }
  }, [selectedIndex, flatCommands]);

  const handleClose = () => {
    route.navigate({
      type: "base",
      path: "home"
    });
  };

  // Keyboard handling
  useKeyboard((evt) => {
    // Handle detail view
    if (showDetail) {
      if (evt.name === "escape" || evt.name === "return") {
        evt.preventDefault();
        setShowDetail(false);
      }
      return;
    }

    switch (evt.name) {
      case "escape":
        evt.preventDefault();
        handleClose();
        break;

      case "up":
      case "k":
        evt.preventDefault();
        setSelectedIndex((prev) =>
          prev > 0 ? prev - 1 : flatCommands.length - 1
        );
        break;

      case "down":
      case "j":
        evt.preventDefault();
        setSelectedIndex((prev) =>
          prev < flatCommands.length - 1 ? prev + 1 : 0
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

  const panelWidth = Math.min(80, dimensions.width - 4);
  const panelHeight = Math.min(30, dimensions.height - 4);

  const selectedCommand = flatCommands[selectedIndex];

  // Detail view
  if (showDetail && selectedCommand) {
    const hasOptions = selectedCommand.options && selectedCommand.options.length > 0;
    const detailHeight = Math.min(hasOptions ? 16 + (selectedCommand.options?.length || 0) * 2 : 12, dimensions.height - 4);

    return (
      <box
        width={dimensions.width}
        height={dimensions.height}
        alignItems="center"
        justifyContent="center"
        position="absolute"
        left={0}
        top={0}
        backgroundColor={colors.overlayBg}
      >
        <box
          width={panelWidth}
          height={detailHeight}
          backgroundColor={colors.panelBg}
          borderColor={colors.greenAccent}
          borderStyle="single"
          flexDirection="column"
        >
          {/* Detail Header */}
          <box width="100%" padding={1} flexDirection="row">
            <text fg={colors.greenAccent}>
              /{selectedCommand.name}
            </text>
            <text fg={colors.dimText}>
              {`  (${selectedCommand.category || "General"})`}
            </text>
          </box>

          {/* Separator */}
          <box width="100%" height={1}>
            <text fg={colors.panelBorder}>{"─".repeat(panelWidth - 2)}</text>
          </box>

          {/* Detail Content */}
          <box width="100%" padding={2} flexDirection="column" flexGrow={1}>
            {/* Description */}
            <text fg={colors.primaryText}>
              {selectedCommand.description || "No description available"}
            </text>

            {/* Aliases */}
            {selectedCommand.aliases && selectedCommand.aliases.length > 0 && (
              <box flexDirection="row" marginTop={1}>
                <text fg={colors.dimText}>Aliases: </text>
                <text fg={colors.primaryText}>
                  {selectedCommand.aliases.map(a => `/${a}`).join(", ")}
                </text>
              </box>
            )}

            {/* Options section */}
            {hasOptions && (
              <>
                <box height={1} />
                <text fg={colors.dimText}>Options:</text>
                <box height={1} />
                {selectedCommand.options?.map((opt, idx) => (
                  <box key={idx} flexDirection="row" paddingLeft={2}>
                    <text fg={colors.greenAccent}>
                      {opt.name}
                    </text>
                    {opt.valueHint && (
                      <text fg={colors.dimText}>{` ${opt.valueHint}`}</text>
                    )}
                    <text fg={colors.primaryText}>{`  ${opt.description}`}</text>
                  </box>
                ))}
              </>
            )}
          </box>

          {/* Separator */}
          <box width="100%" height={1}>
            <text fg={colors.panelBorder}>{"─".repeat(panelWidth - 2)}</text>
          </box>

          {/* Detail Footer */}
          <box width="100%" padding={1} flexDirection="row">
            <text fg={colors.dimText}>
              [enter/esc] back
            </text>
          </box>
        </box>
      </box>
    );
  }

  // Main list view
  return (
    <box
      width={dimensions.width}
      height={dimensions.height}
      alignItems="center"
      justifyContent="center"
      position="absolute"
      left={0}
      top={0}
      backgroundColor={colors.overlayBg}
    >
      <box
        width={panelWidth}
        height={panelHeight}
        backgroundColor={colors.panelBg}
        borderColor={colors.panelBorder}
        borderStyle="single"
        flexDirection="column"
      >
        {/* Header */}
        <box width="100%" padding={1} flexDirection="row">
          <text fg={colors.greenAccent}>
            {"Help - Available Commands".padEnd(panelWidth - 20)}
          </text>
          <text fg={colors.dimText}>
            {`${flatCommands.length} commands`}
          </text>
        </box>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={colors.panelBorder}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Column Headers */}
        <box width="100%" paddingLeft={2} paddingRight={2} flexDirection="row">
          <text fg={colors.dimText}>
            {"Command".padEnd(18)}{"Category".padEnd(14)}{"Description"}
          </text>
        </box>

        {/* Commands List - Scrollbox */}
        <scrollbox
          ref={scrollboxRef}
          style={{
            rootOptions: { flexGrow: 1, width: "100%" },
            contentOptions: {
              paddingLeft: 1,
              paddingRight: 1,
              flexDirection: "column",
            },
          }}
          stickyScroll={false}
          focused={true}
        >
          {flatCommands.map((cmd, idx) => {
            const isSelected = idx === selectedIndex;
            const hasOptions = cmd.options && cmd.options.length > 0;
            const name = `/${cmd.name}`.padEnd(17).slice(0, 17);
            const category = (cmd.category || "General").slice(0, 12).padEnd(14);
            const desc = cmd.description || "";
            const optionHint = hasOptions ? " [...]" : "";

            return (
              <box
                key={cmd.name}
                id={cmd.name}
                width="100%"
                backgroundColor={isSelected ? colors.selectedBg : undefined}
                flexDirection="row"
                paddingLeft={1}
              >
                <text fg={isSelected ? colors.greenAccent : colors.primaryText}>
                  {name}
                </text>
                <text fg={colors.dimText}>
                  {category}
                </text>
                <text fg={isSelected ? colors.primaryText : colors.dimText}>
                  {desc}
                </text>
                {hasOptions && (
                  <text fg={colors.greenAccent}>{optionHint}</text>
                )}
              </box>
            );
          })}
        </scrollbox>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={colors.panelBorder}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Footer */}
        <box width="100%" padding={1} flexDirection="row">
          <text fg={colors.dimText}>
            [j/k] navigate  [enter/v] details  [esc] close
          </text>
        </box>
      </box>
    </box>
  );
}
