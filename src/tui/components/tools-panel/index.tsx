/**
 * Tools Panel Component
 *
 * Modal overlay for viewing and managing active tools during a session.
 * Shows tools grouped by category with toggle controls.
 * Press Enter/v to view detailed description of selected tool.
 */

import { useState, useCallback, useEffect, useRef } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { ScrollBoxRenderable } from "@opentui/core";
import { scrollToIndex } from "../../utils/scroll";
import {
  ALL_TOOLS,
  getCategoryDisplayName,
  countEnabledTools,
  type ToolCategory,
  type ToolsetState,
  type ToolDefinition,
} from "../../../core/toolset";
import { sessions, type SessionInfo } from "../../../core/session";
import { useTheme } from "../../theme";

interface ToolsPanelProps {
  open: boolean;
  onClose: () => void;
  session: SessionInfo;
  onToolsetChange?: (toolsetState: ToolsetState) => void;
}

export default function ToolsPanel({
  open,
  onClose,
  session,
  onToolsetChange,
}: ToolsPanelProps) {
  const { colors } = useTheme();
  const dimensions = useTerminalDimensions();
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [categoryFilter, setCategoryFilter] = useState<ToolCategory | null>(
    null,
  );
  const [showDetail, setShowDetail] = useState(false);
  const [toolsetState, setToolsetState] = useState<ToolsetState | null>(
    session.config?.toolsetState || null,
  );
  const scrollboxRef = useRef<ScrollBoxRenderable | null>(null);

  // Get filtered tools
  const getFilteredTools = useCallback((): ToolDefinition[] => {
    if (categoryFilter === null) {
      return ALL_TOOLS;
    }
    return ALL_TOOLS.filter((t) => t.category === categoryFilter);
  }, [categoryFilter]);

  const filteredTools = getFilteredTools();

  // Ensure selected index is within bounds when filter changes
  useEffect(() => {
    if (selectedIndex >= filteredTools.length) {
      setSelectedIndex(Math.max(0, filteredTools.length - 1));
    }
  }, [filteredTools.length, selectedIndex]);

  // Scroll to keep selected item in view
  useEffect(() => {
    scrollToIndex(
      scrollboxRef.current,
      selectedIndex,
      filteredTools,
      (t) => t.id,
    );
  }, [selectedIndex, filteredTools]);

  // Check if a tool is enabled
  const isToolEnabled = useCallback(
    (toolId: string): boolean => {
      if (!toolsetState) return true;
      return toolsetState.enabledTools[toolId] ?? true;
    },
    [toolsetState],
  );

  // Toggle a tool
  const toggleTool = useCallback(
    async (toolId: string) => {
      const currentEnabled = isToolEnabled(toolId);
      const newEnabled = !currentEnabled;

      const newState: ToolsetState = toolsetState
        ? {
            ...toolsetState,
            enabledTools: {
              ...toolsetState.enabledTools,
              [toolId]: newEnabled,
            },
            lastModified: Date.now(),
          }
        : {
            baseToolsetId: "web-pentest",
            enabledTools: { [toolId]: newEnabled },
            lastModified: Date.now(),
          };

      setToolsetState(newState);

      try {
        await sessions.toggleTool(session.id, toolId, newEnabled);
        onToolsetChange?.(newState);
      } catch (e) {
        console.error("Failed to toggle tool:", e);
      }
    },
    [toolsetState, isToolEnabled, session.id, onToolsetChange],
  );

  // Keyboard handling
  useKeyboard((evt) => {
    if (!open) return;

    // Handle detail view
    if (showDetail) {
      if (evt.name === "escape" || evt.name === "return" || evt.name === "v") {
        evt.preventDefault();
        setShowDetail(false);
      }
      return;
    }

    switch (evt.name) {
      case "escape":
        evt.preventDefault();
        onClose();
        break;

      case "up":
      case "k":
        evt.preventDefault();
        setSelectedIndex((prev) =>
          prev > 0 ? prev - 1 : filteredTools.length - 1,
        );
        break;

      case "down":
      case "j":
        evt.preventDefault();
        setSelectedIndex((prev) =>
          prev < filteredTools.length - 1 ? prev + 1 : 0,
        );
        break;

      case "space":
        evt.preventDefault();
        if (filteredTools[selectedIndex]) {
          toggleTool(filteredTools[selectedIndex].id);
        }
        break;

      case "return":
      case "v":
        evt.preventDefault();
        if (filteredTools[selectedIndex]) {
          setShowDetail(true);
        }
        break;

      // Number keys for category filter
      case "0":
        evt.preventDefault();
        setCategoryFilter(null);
        break;
      case "1":
        evt.preventDefault();
        setCategoryFilter("reconnaissance");
        break;
      case "2":
        evt.preventDefault();
        setCategoryFilter("exploitation");
        break;
      case "3":
        evt.preventDefault();
        setCategoryFilter("browser");
        break;
      case "4":
        evt.preventDefault();
        setCategoryFilter("reporting");
        break;
      case "5":
        evt.preventDefault();
        setCategoryFilter("utility");
        break;
    }
  });

  if (!open) return null;

  const { enabled, total } = countEnabledTools(toolsetState || undefined);
  const panelWidth = Math.min(90, dimensions.width - 4);
  const panelHeight = Math.min(35, dimensions.height - 4);

  // Category labels for filter
  const categories: { key: ToolCategory | null; label: string }[] = [
    { key: null, label: "All" },
    { key: "reconnaissance", label: "Recon" },
    { key: "exploitation", label: "Exploit" },
    { key: "browser", label: "Browser" },
    { key: "reporting", label: "Report" },
    { key: "utility", label: "Utility" },
  ];

  const selectedTool = filteredTools[selectedIndex];

  // Detail view
  if (showDetail && selectedTool) {
    return (
      <box
        width={dimensions.width}
        height={dimensions.height}
        alignItems="center"
        justifyContent="center"
        position="absolute"
        left={0}
        top={0}
        backgroundColor={colors.backgroundOverlay}
      >
        <box
          width={panelWidth}
          height={20}
          backgroundColor={colors.backgroundPanel}
          borderColor={colors.primary}
          borderStyle="single"
          flexDirection="column"
        >
          {/* Detail Header */}
          <box width="100%" padding={1} flexDirection="row">
            <text fg={colors.primary}>{selectedTool.name}</text>
            <text
              fg={colors.textMuted}
            >{`  (${getCategoryDisplayName(selectedTool.category)})`}</text>
          </box>

          {/* Separator */}
          <box width="100%" height={1}>
            <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
          </box>

          {/* Detail Content */}
          <box width="100%" padding={2} flexDirection="column" flexGrow={1}>
            <box flexDirection="row">
              <text fg={colors.textMuted}>Tool ID: </text>
              <text fg={colors.text}>{selectedTool.id}</text>
            </box>
            <box flexDirection="row">
              <text fg={colors.textMuted}>Status: </text>
              <text
                fg={
                  isToolEnabled(selectedTool.id)
                    ? colors.primary
                    : colors.textMuted
                }
              >
                {isToolEnabled(selectedTool.id) ? "Enabled" : "Disabled"}
              </text>
            </box>
            <box height={1} />
            <text fg={colors.text}>
              {selectedTool.detail || selectedTool.description}
            </text>
          </box>

          {/* Separator */}
          <box width="100%" height={1}>
            <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
          </box>

          {/* Detail Footer */}
          <box width="100%" padding={1} flexDirection="row">
            <text fg={colors.textMuted}>[space] toggle [enter/esc] back</text>
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
      backgroundColor={colors.backgroundOverlay}
    >
      <box
        width={panelWidth}
        height={panelHeight}
        backgroundColor={colors.backgroundPanel}
        borderColor={colors.border}
        borderStyle="single"
        flexDirection="column"
      >
        {/* Header */}
        <box width="100%" padding={1} flexDirection="row">
          <text fg={colors.primary}>
            {"Tools Panel".padEnd(panelWidth - 22)}
          </text>
          <text fg={colors.textMuted}>{`${enabled}/${total} enabled`}</text>
        </box>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Category Filter */}
        <box width="100%" padding={1} flexDirection="row">
          <text fg={colors.textMuted}>Filter: </text>
          {categories.map((cat, idx) => {
            const isActive = categoryFilter === cat.key;
            return (
              <text key={idx} fg={isActive ? colors.primary : colors.textMuted}>
                {`[${idx}]${cat.label} `}
              </text>
            );
          })}
        </box>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Column Headers */}
        <box width="100%" paddingLeft={2} paddingRight={2} flexDirection="row">
          <text fg={colors.textMuted}>
            {"     Name".padEnd(22)}
            {"Category".padEnd(12)}
            {"Description"}
          </text>
        </box>

        {/* Tools List - Scrollbox */}
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
          {filteredTools.map((tool, idx) => {
            const isSelected = idx === selectedIndex;
            const isEnabled = isToolEnabled(tool.id);
            const checkbox = isEnabled ? "[x]" : "[ ]";
            const name = tool.name.padEnd(18).slice(0, 18);
            const cat = getCategoryDisplayName(tool.category)
              .slice(0, 10)
              .padEnd(12);
            const desc = tool.description;

            return (
              <box
                key={tool.id}
                id={tool.id}
                width="100%"
                backgroundColor={
                  isSelected ? colors.backgroundSelected : undefined
                }
                flexDirection="row"
                paddingLeft={1}
              >
                <text fg={isSelected ? colors.text : colors.textMuted}>
                  {checkbox}
                </text>
                <text
                  fg={isEnabled ? colors.primary : colors.textMuted}
                >{` ${name}`}</text>
                <text fg={colors.textMuted}>{cat}</text>
                <text fg={isSelected ? colors.text : colors.textMuted}>
                  {desc}
                </text>
              </box>
            );
          })}
        </scrollbox>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Footer */}
        <box width="100%" padding={1} flexDirection="row">
          <text fg={colors.textMuted}>
            [j/k] navigate [space] toggle [enter/v] details [0-5] filter [esc]
            close
          </text>
        </box>
      </box>
    </box>
  );
}
