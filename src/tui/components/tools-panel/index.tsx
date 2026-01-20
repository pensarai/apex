/**
 * Tools Panel Component
 *
 * Modal overlay for viewing and managing active tools during a session.
 * Shows tools grouped by category with toggle controls.
 * Press Enter/v to view detailed description of selected tool.
 */

import { useState, useCallback, useEffect, useRef } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { RGBA, ScrollBoxRenderable } from "@opentui/core";
import {
  ALL_TOOLS,
  getCategoryDisplayName,
  countEnabledTools,
  type ToolCategory,
  type ToolsetState,
  type ToolDefinition,
} from "../../../core/toolset";
import { Session } from "../../../core/session";

// Colors
const bgOverlay = RGBA.fromInts(0, 0, 0, 200);
const bgPanel = RGBA.fromInts(20, 20, 20, 255);
const borderColor = RGBA.fromInts(60, 60, 60, 255);
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const selectedBg = RGBA.fromInts(40, 40, 60, 255);
const white = RGBA.fromInts(255, 255, 255, 255);

interface ToolsPanelProps {
  open: boolean;
  onClose: () => void;
  session: Session.SessionInfo;
  onToolsetChange?: (toolsetState: ToolsetState) => void;
}

export default function ToolsPanel({
  open,
  onClose,
  session,
  onToolsetChange,
}: ToolsPanelProps) {
  const dimensions = useTerminalDimensions();
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [categoryFilter, setCategoryFilter] = useState<ToolCategory | null>(null);
  const [showDetail, setShowDetail] = useState(false);
  const [toolsetState, setToolsetState] = useState<ToolsetState | null>(
    session.config?.toolsetState || null
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

  // Scroll to keep selected item in view (only when out of view)
  useEffect(() => {
    if (!scrollboxRef.current || filteredTools.length === 0) return;

    const scroll = scrollboxRef.current;
    const viewportHeight = scroll.height;
    const children = scroll.getChildren();

    // Find the selected item element
    const selectedTool = filteredTools[selectedIndex];
    if (!selectedTool) return;

    const target = children.find(child => child.id === selectedTool.id);
    if (!target) return;

    // Calculate target's visual position relative to the scroll container
    const targetVisualY = target.y - scroll.y;
    const targetHeight = target.height || 1;

    // Check if target is below visible area
    if (targetVisualY + targetHeight > viewportHeight) {
      scroll.scrollBy(targetVisualY - viewportHeight + targetHeight + 1);
    }
    // Check if target is above visible area
    else if (targetVisualY < 0) {
      scroll.scrollBy(targetVisualY);
    }
  }, [selectedIndex, filteredTools]);

  // Check if a tool is enabled
  const isToolEnabled = useCallback(
    (toolId: string): boolean => {
      if (!toolsetState) return true;
      return toolsetState.enabledTools[toolId] ?? true;
    },
    [toolsetState]
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
        await Session.toggleTool(session.id, toolId, newEnabled);
        onToolsetChange?.(newState);
      } catch (e) {
        console.error("Failed to toggle tool:", e);
      }
    },
    [toolsetState, isToolEnabled, session.id, onToolsetChange]
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
          prev > 0 ? prev - 1 : filteredTools.length - 1
        );
        break;

      case "down":
      case "j":
        evt.preventDefault();
        setSelectedIndex((prev) =>
          prev < filteredTools.length - 1 ? prev + 1 : 0
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
        backgroundColor={bgOverlay}
      >
        <box
          width={panelWidth}
          height={20}
          backgroundColor={bgPanel}
          borderColor={greenAccent}
          borderStyle="single"
          flexDirection="column"
        >
          {/* Detail Header */}
          <box width="100%" padding={1} flexDirection="row">
            <text fg={greenAccent}>
              {selectedTool.name}
            </text>
            <text fg={dimText}>
              {`  (${getCategoryDisplayName(selectedTool.category)})`}
            </text>
          </box>

          {/* Separator */}
          <box width="100%" height={1}>
            <text fg={borderColor}>{"─".repeat(panelWidth - 2)}</text>
          </box>

          {/* Detail Content */}
          <box width="100%" padding={2} flexDirection="column" flexGrow={1}>
            <box flexDirection="row">
              <text fg={dimText}>Tool ID: </text>
              <text fg={white}>{selectedTool.id}</text>
            </box>
            <box flexDirection="row">
              <text fg={dimText}>Status:  </text>
              <text fg={isToolEnabled(selectedTool.id) ? greenAccent : dimText}>
                {isToolEnabled(selectedTool.id) ? "Enabled" : "Disabled"}
              </text>
            </box>
            <box height={1} />
            <text fg={white}>
              {selectedTool.detail || selectedTool.description}
            </text>
          </box>

          {/* Separator */}
          <box width="100%" height={1}>
            <text fg={borderColor}>{"─".repeat(panelWidth - 2)}</text>
          </box>

          {/* Detail Footer */}
          <box width="100%" padding={1} flexDirection="row">
            <text fg={dimText}>
              [space] toggle  [enter/esc] back
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
      backgroundColor={bgOverlay}
    >
      <box
        width={panelWidth}
        height={panelHeight}
        backgroundColor={bgPanel}
        borderColor={borderColor}
        borderStyle="single"
        flexDirection="column"
      >
        {/* Header */}
        <box width="100%" padding={1} flexDirection="row">
          <text fg={greenAccent}>
            {"Tools Panel".padEnd(panelWidth - 22)}
          </text>
          <text fg={dimText}>
            {`${enabled}/${total} enabled`}
          </text>
        </box>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={borderColor}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Category Filter */}
        <box width="100%" padding={1} flexDirection="row">
          <text fg={dimText}>Filter: </text>
          {categories.map((cat, idx) => {
            const isActive = categoryFilter === cat.key;
            return (
              <text key={idx} fg={isActive ? greenAccent : dimText}>
                {`[${idx}]${cat.label} `}
              </text>
            );
          })}
        </box>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={borderColor}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Column Headers */}
        <box width="100%" paddingLeft={2} paddingRight={2} flexDirection="row">
          <text fg={dimText}>
            {"     Name".padEnd(22)}{"Category".padEnd(12)}{"Description"}
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
            const cat = getCategoryDisplayName(tool.category).slice(0, 10).padEnd(12);
            const desc = tool.description;

            return (
              <box
                key={tool.id}
                id={tool.id}
                width="100%"
                backgroundColor={isSelected ? selectedBg : undefined}
                flexDirection="row"
                paddingLeft={1}
              >
                <text fg={isSelected ? white : dimText}>
                  {checkbox}
                </text>
                <text fg={isEnabled ? greenAccent : dimText}>
                  {` ${name}`}
                </text>
                <text fg={dimText}>
                  {cat}
                </text>
                <text fg={isSelected ? white : dimText}>
                  {desc}
                </text>
              </box>
            );
          })}
        </scrollbox>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={borderColor}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Footer */}
        <box width="100%" padding={1} flexDirection="row">
          <text fg={dimText}>
            [j/k] navigate  [space] toggle  [enter/v] details  [0-5] filter  [esc] close
          </text>
        </box>
      </box>
    </box>
  );
}
