/**
 * Theme Picker — /themes command
 *
 * Scrollable list of all registered themes with live preview.
 * Navigating applies the theme temporarily; Enter confirms and persists.
 * Escape reverts to the previous theme.
 */

import { useState, useCallback, useRef } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { useTheme } from "../../theme";
import { useRoute } from "../../context/route";
import { update as updateConfig } from "../../../core/config";

export default function ThemePicker() {
  const dimensions = useTerminalDimensions();
  const route = useRoute();
  const {
    colors,
    theme,
    mode,
    availableThemes,
    setTheme,
    toggleMode,
    setMode,
  } = useTheme();

  const [selectedIndex, setSelectedIndex] = useState(() =>
    Math.max(0, availableThemes.indexOf(theme.name)),
  );
  const originalThemeRef = useRef(theme.name);
  const originalModeRef = useRef(mode);

  const handleClose = useCallback(() => {
    // Revert to original theme
    setTheme(originalThemeRef.current);
    setMode(originalModeRef.current);
    route.navigate({ type: "base", path: "home" });
  }, [setTheme, setMode, route]);

  const handleConfirm = useCallback(async () => {
    // Persist the current theme and mode
    const currentThemeName = availableThemes[selectedIndex];
    if (currentThemeName) {
      await updateConfig({ theme: currentThemeName });
    }
    route.navigate({ type: "base", path: "home" });
  }, [availableThemes, selectedIndex, route]);

  useKeyboard((evt) => {
    if (evt.name === "escape") {
      handleClose();
      return;
    }

    if (evt.name === "return") {
      handleConfirm();
      return;
    }

    if (evt.name === "up" || (evt.name === "k" && !evt.ctrl)) {
      setSelectedIndex((prev) => {
        const next = prev <= 0 ? availableThemes.length - 1 : prev - 1;
        if (availableThemes[next]) setTheme(availableThemes[next]);
        return next;
      });
      return;
    }

    if (evt.name === "down" || (evt.name === "j" && !evt.ctrl)) {
      setSelectedIndex((prev) => {
        const next = prev >= availableThemes.length - 1 ? 0 : prev + 1;
        if (availableThemes[next]) setTheme(availableThemes[next]);
        return next;
      });
      return;
    }

    // Toggle dark/light mode with 'm' or 't'
    if (evt.name === "m" || evt.name === "t") {
      toggleMode();
      // Persist mode change
      const newMode = mode === "dark" ? "light" : "dark";
      updateConfig({ themeMode: newMode });
      return;
    }
  });

  const panelWidth = Math.min(50, dimensions.width - 4);
  const panelHeight = Math.min(
    availableThemes.length + 6,
    dimensions.height - 4,
  );

  // Calculate visible window for scrolling
  const listHeight = panelHeight - 5; // header + footer + borders
  const scrollOffset = Math.max(
    0,
    Math.min(
      selectedIndex - Math.floor(listHeight / 2),
      availableThemes.length - listHeight,
    ),
  );
  const visibleThemes = availableThemes.slice(
    scrollOffset,
    scrollOffset + listHeight,
  );

  return (
    <box
      width={dimensions.width}
      height={dimensions.height}
      alignItems="center"
      justifyContent="center"
      position="absolute"
      left={0}
      top={0}
      backgroundColor={colors.background}
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
        <box
          width="100%"
          paddingLeft={1}
          paddingRight={1}
          flexDirection="row"
          justifyContent="space-between"
        >
          <text fg={colors.primary}>Themes</text>
          <text fg={colors.textMuted}>mode: {mode}</text>
        </box>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Theme List */}
        <box
          flexDirection="column"
          flexGrow={1}
          paddingLeft={1}
          paddingRight={1}
        >
          {visibleThemes.map((themeName) => {
            const actualIndex = availableThemes.indexOf(themeName);
            const isSelected = actualIndex === selectedIndex;
            const isCurrent = themeName === originalThemeRef.current;

            return (
              <box key={themeName} flexDirection="row">
                <text fg={isSelected ? colors.primary : colors.textMuted}>
                  {isSelected ? "❯ " : "  "}
                </text>
                <text fg={isSelected ? colors.primary : colors.text}>
                  {themeName}
                </text>
                {isCurrent && <text fg={colors.textMuted}> (current)</text>}
              </box>
            );
          })}
        </box>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Footer */}
        <box width="100%" paddingLeft={1} paddingRight={1} flexDirection="row">
          <text fg={colors.textMuted}>
            [↑↓] browse [enter] select [m] toggle mode [esc] cancel
          </text>
        </box>
      </box>
    </box>
  );
}
